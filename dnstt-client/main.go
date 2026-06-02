// dnstt-client is the client end of a DNS tunnel.
//
// Usage:
//
//	dnstt-client [-doh URL|-dot ADDR|-udp ADDR] -pubkey-file PUBKEYFILE DOMAIN LOCALADDR
//
// Examples:
//
//	dnstt-client -doh https://resolver.example/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:7000
//	dnstt-client -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000
//
// The program supports DNS over HTTPS (DoH), DNS over TLS (DoT), and UDP DNS.
// Use one of these options:
//
//	-doh https://resolver.example/dns-query
//	-dot resolver.example:853
//	-udp resolver.example:53
//
// You can give the server's public key as a file or as a hex string. Use
// "dnstt-server -gen-key" to get the public key.
//
//	-pubkey-file server.pub
//	-pubkey 0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// LOCALADDR is the TCP address that will listen for connections and forward
// them over the tunnel.
//
// In -doh and -dot modes, the program's TLS fingerprint is camouflaged with
// uTLS by default. The specific TLS fingerprint is selected randomly from a
// weighted distribution. You can set your own distribution (or specific single
// fingerprint) using the -utls option. The special value "none" disables uTLS.
//
//	-utls '3*Firefox,2*Chrome,1*iOS'
//	-utls Firefox
//	-utls none
package dnsttclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name.
func dnsNameCapacity(domain dns.Name) int {
	// Names must be 255 octets or shorter in total length.
	// https://tools.ietf.org/html/rfc1035#section-2.3.4
	capacity := 255
	// Subtract the length of the null terminator.
	capacity -= 1
	for _, label := range domain {
		// Subtract the length of the label and the length octet.
		capacity -= len(label) + 1
	}
	// Each label may be up to 63 bytes long and requires 64 bytes to
	// encode.
	capacity = capacity * 63 / 64
	// Base32 expands every 5 bytes to 8.
	capacity = capacity * 5 / 8
	return capacity
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// sampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func sampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

func handle(local *net.TCPConn, sess *smux.Session, conv uint32) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("session %08x opening stream: %v", conv, err)
	}
	defer func() {
		log.Printf("[DNSTT] end stream %08x:%d", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("[DNSTT] begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var buf [1024]byte
		n, err := local.Read(buf[:])
		if n > 0 {
			log.Printf("[DNSTT] stream %08x:%d first %d bytes from local: %x", conv, stream.ID(), n, buf[:n])
			stream.Write(buf[:n])
		}
		if err == nil {
			_, err = io.Copy(stream, local)
		}
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("[DNSTT] stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		var buf [1024]byte
		n, err := stream.Read(buf[:])
		if n > 0 {
			log.Printf("[DNSTT] stream %08x:%d first %d bytes from stream: %x", conv, stream.ID(), n, buf[:n])
			local.Write(buf[:n])
		}
		if err == nil {
			_, err = io.Copy(local, stream)
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("[DNSTT] stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()
	return nil
}

func run(pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn, cancelCtx context.Context, ready chan<- string) error {
	defer pconn.Close()

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	defer ln.Close()

	listenAddr := ln.Addr().String()
	if ready != nil {
		ready <- listenAddr
	}

	// Cancel context handler
	go func() {
		<-cancelCtx.Done()
		ln.Close()
		pconn.Close()
	}()

	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1 // clientid + padding length prefix + padding + data length prefix
	if mtu < 80 {
		return fmt.Errorf("domain %s leaves only %d bytes for payload", domain, mtu)
	}
	log.Printf("effective MTU %d", mtu)

	// Open a KCP conn on the PacketConn.
	conn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
	if err != nil {
		return fmt.Errorf("opening KCP conn: %v", err)
	}
	defer func() {
		log.Printf("end session %08x", conn.GetConv())
		conn.Close()
	}()
	log.Printf("begin session %08x", conn.GetConv())
	// Permit coalescing the payloads of consecutive sends.
	conn.SetStreamMode(true)
	// Disable the dynamic congestion window (limit only by the maximum of
	// local and remote static windows).
	conn.SetNoDelay(
		0, // default nodelay
		0, // default interval
		0, // default resend
		1, // nc=1 => congestion window off
	)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if rc := conn.SetMtu(mtu); !rc {
		panic(rc)
	}

	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewClient(conn, pubkey)
	if err != nil {
		return err
	}

	// Start a smux session on the Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		return fmt.Errorf("opening smux session: %v", err)
	}
	defer sess.Close()

	// Cancel context handler for smux session
	go func() {
		<-cancelCtx.Done()
		sess.Close()
	}()

	for {
		local, err := ln.Accept()
		if err != nil {
			select {
			case <-cancelCtx.Done():
				return nil
			default:
			}
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		go func() {
			defer local.Close()
			err := handle(local.(*net.TCPConn), sess, conn.GetConv())
			if err != nil {
				log.Printf("handle: %v", err)
			}
		}()
	}
}

func RunDNSTT(pubkeyStr, domainStr, localAddrStr, remoteResolverStr, utlsFingerprint string, cancelCtx context.Context, ready chan<- string) error {
	log.Printf("[DNSTT] RunDNSTT starting: pubkey=%s domain=%s local=%s remote=%s", pubkeyStr, domainStr, localAddrStr, remoteResolverStr)

	pubkey, err := noise.DecodeKey(pubkeyStr)
	if err != nil {
		log.Printf("[DNSTT] Pubkey decode error: %v", err)
		return fmt.Errorf("pubkey format error: %v", err)
	}

	domain, err := dns.ParseName(domainStr)
	if err != nil {
		log.Printf("[DNSTT] Domain parse error: %v", err)
		return fmt.Errorf("invalid domain name %q: %v", domainStr, err)
	}

	localAddr, err := net.ResolveTCPAddr("tcp", localAddrStr)
	if err != nil {
		log.Printf("[DNSTT] Local addr resolve error: %v", err)
		return fmt.Errorf("resolving local addr %q: %v", localAddrStr, err)
	}
	utlsClientHelloID, err := sampleUTLSDistribution(utlsFingerprint)
	if err != nil {
		return fmt.Errorf("parsing utls fingerprint: %v", err)
	}

	var remoteAddr net.Addr
	var pconn net.PacketConn

	if strings.HasPrefix(remoteResolverStr, "https://") {
		log.Printf("[DNSTT] Using DoH: %s", remoteResolverStr)
		dohURL := remoteResolverStr
		addr := turbotunnel.DummyAddr{}
		var rt http.RoundTripper
		if utlsClientHelloID == nil {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = nil
			rt = transport
		} else {
			rt = NewUTLSRoundTripper(nil, utlsClientHelloID)
		}
		pconn, err = NewHTTPPacketConn(rt, dohURL, 32)
		remoteAddr = addr
	} else if strings.HasPrefix(remoteResolverStr, "tls://") || strings.HasPrefix(remoteResolverStr, "dot://") || strings.HasSuffix(remoteResolverStr, ":853") {
		log.Printf("[DNSTT] Using DoT: %s", remoteResolverStr)
		dotAddr := remoteResolverStr
		dotAddr = strings.TrimPrefix(dotAddr, "tls://")
		dotAddr = strings.TrimPrefix(dotAddr, "dot://")

		addr := turbotunnel.DummyAddr{}
		var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
		if utlsClientHelloID == nil {
			dialTLSContext = (&tls.Dialer{}).DialContext
		} else {
			dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
			}
		}
		pconn, err = NewTLSPacketConn(dotAddr, dialTLSContext)
		remoteAddr = addr
	} else {
		log.Printf("[DNSTT] Using UDP: %s", remoteResolverStr)
		udpAddr := remoteResolverStr
		// If it's just an IP without port, add :53
		if !strings.Contains(udpAddr, ":") || (strings.HasPrefix(udpAddr, "[") && !strings.Contains(udpAddr, "]:")) {
			udpAddr = net.JoinHostPort(udpAddr, "53")
		}

		addr, err2 := net.ResolveUDPAddr("udp", udpAddr)
		if err2 != nil {
			log.Printf("[DNSTT] UDP resolve error: %v", err2)
			return fmt.Errorf("resolving UDP addr %q: %v", udpAddr, err2)
		}
		pconn, err = net.ListenUDP("udp", nil)
		remoteAddr = addr
	}

	if err != nil {
		return fmt.Errorf("resolving remote resolver: %v", err)
	}

	pconn = NewDNSPacketConn(pconn, remoteAddr, domain)
	return run(pubkey, domain, localAddr, remoteAddr, pconn, cancelCtx, ready)
}
