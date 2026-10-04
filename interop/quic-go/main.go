// SPDX-License-Identifier: BSD-2-Clause

// The quic-go interop harness for ssh3-c (D3/D4/P3 acceptance).
//
// One binary, several modes:
//
//	harness -server -addr 127.0.0.1:0 -cert cert.pem -key key.pem
//	harness -client -addr 127.0.0.1:4433 -count 8 -size 512
//	harness -client -streams -addr 127.0.0.1:4433 -count 8 -size 65536
//	harness -h3-server -addr 127.0.0.1:4433 -cert cert.pem -key key.pem
//	harness -h3-client -a 127.0.0.1:4433
//
// The server accepts QUIC connections and echoes every received
// DATAGRAM back; in addition it echoes every accepted stream.  The
// client dials and either sends count datagrams of the requested
// size (verifying the echoes byte for byte) or, with -streams,
// pumps count*size bytes through a stream against a deterministic
// pattern (no memory bound, for the bulk runs).
//
// The -h3-* modes exercise RFC 9220 extended CONNECT over HTTP/3:
// the server accepts only CONNECT with :protocol=ssh3, :path=/ssh3-term
// and a non-empty Authorization header (401 otherwise), answers 200
// and holds the request stream open until the peer closes it; the
// client opens the extended CONNECT with Authorization: test-token
// and reports the response status.
//
// Machine-readable lines on stdout (the runner greps them):
//
//	INTEROP-LISTEN port=N
//	INTEROP-HANDSHAKE-OK
//	INTEROP-DATAGRAM-OK sent=N recv=N
//	INTEROP-STREAM-OK sent=N recv=N
//	INTEROP-H3-CONNECT-OK authlen=<len>
//	INTEROP-H3-STATUS <code>
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go/qlog"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "harness: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	server := flag.Bool("server", false, "run as a datagram echo server")
	client := flag.Bool("client", false, "run as a datagram test client")
	addr := flag.String("addr", "127.0.0.1:0", "listen or dial address")
	certFile := flag.String("cert", "", "server certificate PEM (server mode)")
	keyFile := flag.String("key", "", "server key PEM (server mode)")
	alpn := flag.String("alpn", "s3interop/1", "QUIC ALPN")
	count := flag.Int("count", 8, "datagrams the client sends")
	size := flag.Int("size", 512, "datagram or stream chunk size (client)")
	timeout := flag.Duration("timeout", 20*time.Second, "overall deadline (client)")
	keylog := flag.String("keylog", "", "NSS keylog file for the client TLS secrets")
	streams := flag.Bool("streams", false, "client test: pump a stream instead of datagrams")
	hold := flag.Duration("hold", 0, "after the handshake, hold the connection idle this long")
	min := flag.Int("min", -1, "require at least this many echoed datagrams (-1: all)")
	h3Server := flag.Bool("h3-server", false, "run as an HTTP/3 server accepting RFC 9220 extended CONNECT (ssh3)")
	h3Client := flag.Bool("h3-client", false, "run as an HTTP/3 extended CONNECT client (ssh3)")
	addrShort := flag.String("a", "", "dial target host:port for -h3-client (alias for -addr)")
	flag.Parse()

	if !*streams && *size > 1100 {
		// the datagram must fit the 1200 byte max_datagram_frame_size
		// advertised by the ssh3-c runners with a frame header on top
		*size = 1100
	}

	modes := 0
	for _, m := range []*bool{server, client, h3Server, h3Client} {
		if *m {
			modes++
		}
	}
	if modes > 1 {
		fatalf("-server, -client, -h3-server and -h3-client are mutually exclusive")
	}

	if *server {
		runServer(*addr, *certFile, *keyFile, *alpn, *keylog)
		return
	}

	if *h3Server {
		runH3Server(*addr, *certFile, *keyFile)
		return
	}

	if *h3Client {
		target := *addr
		if *addrShort != "" {
			target = *addrShort
		}
		runH3Client(target, *timeout)
		return
	}

	if *hold > 0 {
		runClientHold(*addr, *alpn, *timeout, *keylog, *hold)
		return
	}

	if *streams {
		runClientStreams(*addr, *alpn, *count, *size, *timeout, *keylog)
		return
	}

	runClient(*addr, *alpn, *count, *size, *timeout, *keylog, *min)
}

func udpAddr(addr string) *net.UDPAddr {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fatalf("resolve %s: %v", addr, err)
	}

	return ua
}

func runServer(addr, certFile, keyFile, alpn, keylog string) {
	if certFile == "" || keyFile == "" {
		fatalf("server mode needs -cert and -key")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fatalf("load key pair: %v", err)
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpn},
	}

	if keylog != "" {
		f, err := os.OpenFile(keylog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			fatalf("keylog: %v", err)
		}
		defer f.Close()

		serverTLS.KeyLogWriter = f
	}

	udpConn, err := net.ListenUDP("udp", udpAddr(addr))
	if err != nil {
		fatalf("listen udp: %v", err)
	}

	fmt.Printf("INTEROP-LISTEN port=%d\n", udpConn.LocalAddr().(*net.UDPAddr).Port)

	tr := &quic.Transport{Conn: udpConn}

	listener, err := tr.Listen(serverTLS, &quic.Config{
		MaxIdleTimeout:  60 * time.Second,
		EnableDatagrams: true,
	})
	if err != nil {
		fatalf("listen: %v", err)
	}
	defer listener.Close()

	ctx := context.Background()

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			fatalf("accept: %v", err)
		}

		fmt.Println("INTEROP-HANDSHAKE-OK")

		go func() {
			<-conn.Context().Done()
			fmt.Fprintf(os.Stderr, "harness: server conn closed: %v\n", conn.Context().Err())
		}()

		go echoDatagrams(conn)
		go acceptStreams(conn)
	}
}

func echoDatagrams(conn *quic.Conn) {
	for {
		data, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}

		if err := conn.SendDatagram(data); err != nil {
			return
		}
	}
}

// acceptStreams echoes every incoming stream until the connection
// dies; the io.Copy keeps no bound on the transferred volume
func acceptStreams(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		go func() {
			defer stream.Close()

			if _, err := io.Copy(stream, stream); err != nil {
				stream.CancelRead(0)
			}
		}()
	}
}

// runClientHold dials and then stays silent: the idle-timeout probe
// of the server under test
func runClientHold(addr, alpn string, timeout time.Duration, keylog string, hold time.Duration) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		fatalf("local udp: %v", err)
	}

	tr := &quic.Transport{Conn: udpConn}

	tlsCfg := &tls.Config{
		NextProtos:         []string{alpn},
		InsecureSkipVerify: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout+hold)
	defer cancel()

	conn, err := tr.Dial(ctx, udpAddr(addr), tlsCfg, &quic.Config{
		MaxIdleTimeout: 120 * time.Second,
	})
	if err != nil {
		fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	fmt.Println("INTEROP-HANDSHAKE-OK")

	select {
	case <-time.After(hold):
		fmt.Println("INTEROP-HOLD-DONE connection still alive")
	case <-conn.Context().Done():
		fmt.Printf("INTEROP-CONN-CLOSED: %v\n", conn.Context().Err())
	}
}

func runClient(addr, alpn string, count, size int, timeout time.Duration, keylog string, min int) {
	if count < 1 {
		fatalf("-count must be positive")
	}

	required := count
	if min >= 0 {
		required = min

		if required > count {
			fatalf("-min %d exceeds -count %d", required, count)
		}
	}

	tlsCfg := &tls.Config{
		NextProtos:         []string{alpn},
		InsecureSkipVerify: true, // the harness runs against self-signed certs
	}

	if keylog != "" {
		f, err := os.OpenFile(keylog, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fatalf("keylog: %v", err)
		}
		defer f.Close()

		tlsCfg.KeyLogWriter = f
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		fatalf("local udp: %v", err)
	}

	tr := &quic.Transport{Conn: udpConn}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := tr.Dial(ctx, udpAddr(addr), tlsCfg, &quic.Config{
		MaxIdleTimeout:  60 * time.Second,
		EnableDatagrams: true,
	})
	if err != nil {
		fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	fmt.Println("INTEROP-HANDSHAKE-OK")

	// the payloads carry a little-endian index followed by random
	// bytes; the echo is verified against the stored template

	payloads := make([][]byte, count)
	sent, received := 0, 0

	for i := 0; i < count; i++ {
		p := make([]byte, size)
		binary.LittleEndian.PutUint32(p, uint32(i))

		if _, err := rand.Read(p[4:]); err != nil {
			fatalf("rand: %v", err)
		}

		payloads[i] = p
	}

	for i := 0; i < count; i++ {
		if err := conn.SendDatagram(payloads[i]); err != nil {
			fatalf("send datagram: %v", err)
		}

		sent++
	}

	for received < required {
		data, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			// with RFC 9221 there is no retransmission: under loss
			// the deadline fires before every datagram comes back
			fatalf("receive datagram after %d/%d (required %d): %v", received, count, required,
				err)
		}

		if len(data) != size {
			fatalf("echo %d: bad length %d, want %d", received, len(data), size)
		}

		idx := binary.LittleEndian.Uint32(data)
		if idx >= uint32(count) {
			fatalf("echo: index %d out of range", idx)
		}

		for i := range data {
			if data[i] != payloads[idx][i] {
				fatalf("echo %d: byte %d mismatch", idx, i)
			}
		}

		received++
	}

	fmt.Printf("INTEROP-DATAGRAM-OK sent=%d recv=%d\n", sent, received)
}

// runClientStreams pumps count*size bytes through one stream against
// a deterministic pattern: the writer generator and the verifying
// generator are seeded identically, so nothing is buffered and the
// run scales to the bulk acceptance volume
func runClientStreams(addr, alpn string, count, size int, timeout time.Duration, keylog string) {
	if count < 1 || size < 1 {
		fatalf("-count and -size must be positive")
	}

	total := int64(count) * int64(size)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		fatalf("local udp: %v", err)
	}

	tr := &quic.Transport{Conn: udpConn}

	tlsCfg := &tls.Config{
		NextProtos:         []string{alpn},
		InsecureSkipVerify: true, // the harness runs against self-signed certs
	}

	if keylog != "" {
		f, err := os.OpenFile(keylog, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fatalf("keylog: %v", err)
		}
		defer f.Close()

		tlsCfg.KeyLogWriter = f
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := tr.Dial(ctx, udpAddr(addr), tlsCfg, &quic.Config{
		MaxIdleTimeout: 120 * time.Second,
	})
	if err != nil {
		fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	fmt.Println("INTEROP-HANDSHAKE-OK")

	stream, err := conn.OpenStream()
	if err != nil {
		fatalf("open stream: %v", err)
	}

	pattern := mrand.New(mrand.NewSource(42))

	sent, err := copyPattern(stream, pattern, total)
	if err != nil {
		fatalf("send stream: %v", err)
	}

	if err := stream.Close(); err != nil {
		fatalf("close stream: %v", err)
	}

	verify := mrand.New(mrand.NewSource(42))

	received, err := verifyPattern(stream, verify, total)
	if err != nil {
		fatalf("verify stream: %v", err)
	}

	fmt.Printf("INTEROP-STREAM-OK sent=%d recv=%d\n", sent, received)
}

// copyPattern writes n pattern bytes to w in 16 KiB chunks
func copyPattern(w io.Writer, r *mrand.Rand, n int64) (int64, error) {
	const chunk = 16384

	buf := make([]byte, chunk)

	var written int64

	for written < n {
		next := int64(chunk)
		if rest := n - written; rest < next {
			next = rest
		}

		fillPattern(buf[:next], r)

		m, err := w.Write(buf[:next])
		written += int64(m)

		if err != nil {
			return written, err
		}
	}

	return written, nil
}

// verifyPattern reads n bytes from r and matches them against the
// expected pattern produced by p
func verifyPattern(r io.Reader, p *mrand.Rand, n int64) (int64, error) {
	const chunk = 16384

	want := make([]byte, chunk)
	got := make([]byte, chunk)

	var read int64

	for read < n {
		next := int64(chunk)
		if rest := n - read; rest < next {
			next = rest
		}

		m, err := io.ReadFull(r, got[:next])
		read += int64(m)

		if err != nil {
			return read, err
		}

		fillPattern(want[:next], p)

		for i := int64(0); i < next; i++ {
			if got[i] != want[i] {
				return read, fmt.Errorf("mismatch at offset %d", read-next+int64(i))
			}
		}
	}

	return read, nil
}

// fillPattern fills b with the next bytes of the seeded sequence
func fillPattern(b []byte, r *mrand.Rand) {
	for i := range b {
		b[i] = byte(r.Intn(256))
	}
}

// h3ConnectHandler accepts only RFC 9220 extended CONNECT requests
// announcing the ssh3 protocol; a valid request is answered with 200
// and its stream is kept open until the peer goes away
func h3ConnectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || r.Proto != "ssh3" {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	if r.URL.Path != "/ssh3-term" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	authlen := len(r.Header.Get("Authorization"))
	if authlen == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	fmt.Printf("INTEROP-H3-CONNECT-OK authlen=%d\n", authlen)

	// no Content-Length: a CONNECT response is just a status and the
	// stream carries the tunneled protocol from here on
	w.WriteHeader(http.StatusOK)

	// take over the stream so it stays open until the client closes
	// it; HTTPStream flushes the headers and marks the response as
	// hijacked, so quic-go does not terminate it on handler return
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		return
	}

	str := streamer.HTTPStream()

	_, _ = io.Copy(io.Discard, str) // wait for the client to close

	str.Close()
}

// runH3Server serves HTTP/3 (h3 ALPN is set up automatically by
// quic-go) on the given UDP address
func runH3Server(addr, certFile, keyFile string) {
	if certFile == "" || keyFile == "" {
		fatalf("h3-server mode needs -cert and -key")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fatalf("load key pair: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr(addr))
	if err != nil {
		fatalf("listen udp: %v", err)
	}

	fmt.Printf("INTEROP-LISTEN port=%d\n", udpConn.LocalAddr().(*net.UDPAddr).Port)

	server := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			MaxIdleTimeout: 60 * time.Second,
			Tracer:         qlog.DefaultConnectionTracer, /* QLOGDIR-gated, debug */
		},
		Handler: http.HandlerFunc(h3ConnectHandler),
	}

	if err := server.Serve(udpConn); err != nil {
		fatalf("h3 serve: %v", err)
	}
}

// runH3Client dials, sends the extended CONNECT announcing ssh3 and
// reports the response status.  The request stream's send side stays
// open until the response has been read: Transport.RoundTrip would
// half-close the stream right after the headers (no request body),
// which is not how a real ssh3 client tunnels over the CONNECT.
func runH3Client(target string, timeout time.Duration) {
	if target == "" {
		fatalf("h3-client mode needs -a host:port")
	}

	tlsCfg := &tls.Config{
		NextProtos:         []string{http3.NextProtoH3},
		InsecureSkipVerify: true, // the harness runs against self-signed certs
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		fatalf("local udp: %v", err)
	}

	tr := &quic.Transport{Conn: udpConn}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := tr.Dial(ctx, udpAddr(target), tlsCfg, &quic.Config{
		MaxIdleTimeout: 60 * time.Second,
	})
	if err != nil {
		fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	// extended CONNECT needs the low-level API: NewClientConn is the
	// quic-go-sanctioned entry point for it (RFC 9220)
	cc := (&http3.Transport{}).NewClientConn(conn)

	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		fatalf("open request stream: %v", err)
	}

	req, err := http.NewRequest(http.MethodConnect, "https://"+target+"/ssh3-term", nil)
	if err != nil {
		fatalf("build connect request: %v", err)
	}

	// quic-go encodes req.Proto as the :protocol pseudo-header
	req.Proto = "ssh3"
	req.Header.Set("Authorization", "test-token")

	if err := str.SendRequestHeader(req); err != nil {
		fatalf("send connect: %v", err)
	}

	if err := str.SetDeadline(time.Now().Add(timeout)); err != nil {
		fatalf("set stream deadline: %v", err)
	}

	resp, err := str.ReadResponse()
	if err != nil {
		fatalf("read response: %v", err)
	}

	fmt.Printf("INTEROP-H3-STATUS %d\n", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}

	if err := str.Close(); err != nil {
		fatalf("close stream: %v", err)
	}
}
