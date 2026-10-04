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
//	harness -h3-session-server -addr 127.0.0.1:4433 -cert cert.pem -key key.pem
//	harness -h3-session-client -a 127.0.0.1:4433 [-cmd 'printf s3-exec-ok'] [-kill]
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
// The -h3-session-* modes run the ssh3 session channel on top
// (docs/P4-WIRE.md 2, 3.1, 6): every bidi stream after the CONNECT is
// a channel (header quoting the control stream id, then the 91
// confirmation); the server executes exec requests through sh -c,
// forwards the process output as 94/95 frames and reports the 98
// exit-status; KILL/TERM signals reach the process.  The client opens
// one channel, execs -cmd and expects the exit-status (0 with the
// s3-exec-ok marker, or 137 when -kill signaled KILL).
//
// Machine-readable lines on stdout (the runner greps them):
//
//	INTEROP-LISTEN port=N
//	INTEROP-HANDSHAKE-OK
//	INTEROP-DATAGRAM-OK sent=N recv=N
//	INTEROP-STREAM-OK sent=N recv=N
//	INTEROP-H3-CONNECT-OK authlen=<len>
//	INTEROP-H3-STATUS <code>
//	INTEROP-GO-SESSION-EXEC
//	INTEROP-GO-SESSION-EXIT code=<code>
//	INTEROP-GO-EXEC-OK exit=0 / INTEROP-GO-EXEC-FAIL exit=<code>
//	INTEROP-GO-KILL-OK exit=137 / INTEROP-GO-KILL-FAIL exit=<code>
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
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
	badUA := flag.Bool("bad-ua", false, "h3-client: announce an unsupported version, expect 403")
	addrShort := flag.String("a", "", "dial target host:port for -h3-client (alias for -addr)")
	h3SessionServer := flag.Bool("h3-session-server", false,
		"HTTP/3 server with ssh3 session channels: exec/signals per docs/P4-WIRE.md 6")
	h3SessionClient := flag.Bool("h3-session-client", false,
		"HTTP/3 client opening an ssh3 session channel: exec + exit-status")
	command := flag.String("cmd", "printf s3-exec-ok", "h3-session-client: the command to exec")
	kill := flag.Bool("kill", false,
		"h3-session-client: signal KILL after the confirmation, expect exit 137")
	flag.Parse()

	if !*streams && *size > 1100 {
		// the datagram must fit the 1200 byte max_datagram_frame_size
		// advertised by the ssh3-c runners with a frame header on top
		*size = 1100
	}

	modes := 0
	for _, m := range []*bool{server, client, h3Server, h3Client, h3SessionServer, h3SessionClient} {
		if *m {
			modes++
		}
	}
	if modes > 1 {
		fatalf("-server, -client, -h3-server, -h3-client, -h3-session-server " +
			"and -h3-session-client are mutually exclusive")
	}

	if *server {
		runServer(*addr, *certFile, *keyFile, *alpn, *keylog)
		return
	}

	if *h3Server {
		runH3Server(*addr, *certFile, *keyFile)
		return
	}

	if *h3SessionServer {
		runH3SessionServer(*addr, *certFile, *keyFile)
		return
	}

	if *h3Client {
		target := *addr
		if *addrShort != "" {
			target = *addrShort
		}
		runH3Client(target, *timeout, *badUA)
		return
	}

	if *h3SessionClient {
		target := *addr
		if *addrShort != "" {
			target = *addrShort
		}
		runH3SessionClient(target, *timeout, *command, *kill)
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

// s3VersionString is the version string the ssh3-c endpoints announce
// in the User-Agent field (the reference version.go format); the
// harness mirrors the s3_ssh3_version module verdicts: 403 unless the
// peer version parses and is supported
const s3VersionString = "SSH 3.0 ssh3-c 0.1.0 experimental_spec_version=alpha-00"

// s3VersionSupported mirrors the reference IsVersionSupported(): the
// protocol version must be 3.0 and the spec version ours; the legacy
// reference releases 0.1.3..0.1.5 pass without a spec version
func s3VersionSupported(ua string) bool {
	fields := strings.Fields(ua)
	if len(fields) < 4 {
		return false
	}

	proto := strings.SplitN(fields[1], "_", 2)[0]
	protoParts := strings.Split(proto, ".")
	if len(protoParts) != 2 || protoParts[0] != "3" || protoParts[1] != "0" {
		return false
	}

	sw := strings.Split(fields[3], ".")
	if len(sw) != 3 {
		return false
	}

	spec := ""
	for _, f := range fields[4:] {
		if kv := strings.SplitN(f, "=", 2); len(kv) == 2 && kv[0] == "experimental_spec_version" {
			spec = kv[1]
		}
	}

	if spec == "" {
		if fields[2] != "francoismichel/ssh3" || sw[0] != "0" || sw[1] != "1" {
			return false
		}
		patch := sw[2]
		return patch == "3" || patch == "4" || patch == "5"
	}

	return spec == "alpha-00"
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

	ua := r.Header.Get("User-Agent")
	if !s3VersionSupported(ua) {
		fmt.Fprintf(os.Stderr, "harness: 403 for user-agent %q\n", ua)
		w.WriteHeader(http.StatusForbidden)
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
func runH3Client(target string, timeout time.Duration, badUA bool) {
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
	req.Header.Set("User-Agent", s3VersionString)
	if badUA {
		// a parsable but unsupported spec version: the server must 403
		req.Header.Set("User-Agent", "SSH 3.0 ssh3-c 0.1.0 experimental_spec_version=beta-99")
	}
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

	want := http.StatusOK
	if badUA {
		want = http.StatusForbidden
	}

	if resp.StatusCode != want {
		os.Exit(1)
	}

	if badUA {
		// the negative case is done at the status: no tunnel follows
		return
	}

	if err := str.Close(); err != nil {
		fatalf("close stream: %v", err)
	}
}

// the ssh3 wire primitives (docs/P4-WIRE.md): every integer is a QUIC
// varint (RFC 9000 section 16, the two high bits of the first byte
// encode the length) and an SSHString is a varint length followed by
// the raw bytes

const (
	s3SSHFrameType     = 0xaf3627e6 // SSH_FRAME_TYPE, the channel header marker
	s3ChannelMaxPacket = 30000      // the reference maxPacketSize on both sides
)

func s3AppendVarint(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v))
	case v <= 16383:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v <= 1<<30-1:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

func s3AppendSSHString(b []byte, data []byte) []byte {
	b = s3AppendVarint(b, uint64(len(data)))
	return append(b, data...)
}

func s3ReadVarint(r io.Reader) (uint64, error) {
	var first [1]byte

	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}

	length := 1 << (first[0] >> 6)

	rest := make([]byte, length-1)

	if _, err := io.ReadFull(r, rest); err != nil {
		return 0, err
	}

	v := uint64(first[0] & 0x3f)

	for _, b := range rest {
		v = v<<8 | uint64(b)
	}

	return v, nil
}

// s3ReadSSHString reads one SSHString; the length is capped so a
// corrupted varint cannot trigger a wild allocation
func s3ReadSSHString(r io.Reader) ([]byte, error) {
	n, err := s3ReadVarint(r)
	if err != nil {
		return nil, err
	}

	if n > 1<<20 {
		return nil, fmt.Errorf("ssh string too long: %d", n)
	}

	data := make([]byte, n)

	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}

	return data, nil
}

// runH3SessionServer serves the ssh3 session scenarios: the RFC 9220
// extended CONNECT is answered through the http3 stack (the same
// h3ConnectHandler as the -h3-server mode), but the raw server API
// (http3.Server.NewRawServerConn) keeps the bidi dispatch here: the
// first bidi stream of a connection is the CONNECT (the conversation
// control stream), every later bidi is an ssh3 session channel
// (docs/P4-WIRE.md 1, the reference server dispatch rule).  The plain
// http3.Server accept loop parses every bidi as an HTTP request, so it
// cannot be used for the channels.
//
// Each channel runs on its own goroutine with per-channel exec state;
// the harness peers use one channel per connection in practice.  Only
// exec, signal and exit-status requests exist on this server (the PIN:
// wantReply is ignored, the 92/93/96/97/99/100 messages do not exist).
func runH3SessionServer(addr, certFile, keyFile string) {
	if certFile == "" || keyFile == "" {
		fatalf("h3-session-server mode needs -cert and -key")
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
		},
		Handler: http.HandlerFunc(h3ConnectHandler),
	}

	tr := &quic.Transport{Conn: udpConn}

	listener, err := tr.Listen(server.TLSConfig, server.QUICConfig)
	if err != nil {
		fatalf("listen: %v", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			fatalf("accept: %v", err)
		}

		go serveSessionConn(server, conn)
	}
}

// serveSessionConn runs one accepted QUIC connection: the h3 layer
// (the peer's control/QPACK uni streams and the CONNECT request) is
// fed through the raw server conn, every bidi stream after the first
// is handled as an ssh3 session channel
func serveSessionConn(server *http3.Server, conn *quic.Conn) {
	raw, err := server.NewRawServerConn(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "harness: raw server conn: %v\n", err)
		_ = conn.CloseWithError(0, "")
		return
	}

	go func() {
		for {
			str, err := conn.AcceptUniStream(context.Background())
			if err != nil {
				return
			}
			go raw.HandleUnidirectionalStream(str)
		}
	}()

	var (
		convID   uint64
		haveConv bool
	)

	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		if !haveConv {
			// the first bidi stream is the RFC 9220 extended CONNECT,
			// its StreamID is the conversationStreamID the channels
			// must quote in their headers
			convID = uint64(str.StreamID())
			haveConv = true

			go raw.HandleRequestStream(str)
			continue
		}

		go s3HandleSessionChannel(str, convID)
	}
}

// s3HandleSessionChannel runs one accepted ssh3 session channel: the
// header is checked against the conversation, the 91 confirmation goes
// back and the message loop drives the exec/signals of
// docs/P4-WIRE.md 6 (sh -c for exec, the output rides as 94/95, the
// 98 exit-status closes the channel like the reference channel.Close)
func s3HandleSessionChannel(str *quic.Stream, convID uint64) {
	br := bufio.NewReader(str)

	// the channel header (docs/P4-WIRE.md 2.1): varint frame type,
	// varint conversationStreamID, SSHString type, varint maxPacketSize
	ftype, err := s3ReadVarint(br)
	if err != nil {
		return
	}

	convid, err := s3ReadVarint(br)
	if err != nil {
		return
	}

	ctype, err := s3ReadSSHString(br)
	if err != nil {
		return
	}

	if _, err := s3ReadVarint(br); err != nil { // maxPacketSize
		return
	}

	if ftype != s3SSHFrameType || convid != convID || string(ctype) != "session" {
		// the reference answer to a bad channel is cancel(0)
		str.CancelRead(0)
		str.CancelWrite(0)
		return
	}

	// the 91 confirmation with our maxPacketSize, like confirmChannel()
	if _, err := str.Write(s3AppendVarint(s3AppendVarint(nil, 91), s3ChannelMaxPacket)); err != nil {
		return
	}

	fmt.Printf("INTEROP-CHANNEL-ACCEPT id=%d type=session\n", str.StreamID())

	var (
		wmu   sync.Mutex // serializes every write to the channel stream
		cmd   *exec.Cmd
		stdin io.WriteCloser
	)

	for {
		typ, err := s3ReadVarint(br)
		if err != nil {
			// the stream is over: a client FIN is the process stdin
			// EOF, the exit goroutine finishes the verdict on its own
			wmu.Lock()

			if stdin != nil {
				_ = stdin.Close()
			}

			wmu.Unlock()

			return
		}

		switch typ {
		case 94: // SSH_MSG_CHANNEL_DATA: stdin of the process
			data, err := s3ReadSSHString(br)
			if err != nil {
				return
			}

			wmu.Lock()
			w := stdin
			wmu.Unlock()

			if w != nil {
				// a dead process: the write fails, the data is drained
				_, _ = w.Write(data)
			}

		case 95: // SSH_MSG_CHANNEL_EXTENDED_DATA: drained
			if _, err := s3ReadVarint(br); err != nil { // data type
				return
			}

			if _, err := s3ReadSSHString(br); err != nil {
				return
			}

		case 98: // SSH_MSG_CHANNEL_REQUEST
			rtype, err := s3ReadSSHString(br)
			if err != nil {
				return
			}

			var wantReply [1]byte

			if _, err := io.ReadFull(br, wantReply[:]); err != nil {
				return
			}

			_ = wantReply // parsed and ignored, the PIN of the reference

			switch string(rtype) {
			case "exec":
				command, err := s3ReadSSHString(br)
				if err != nil {
					return
				}

				c := exec.Command("sh", "-c", string(command))

				cin, err := c.StdinPipe()
				if err != nil {
					return
				}

				cout, err := c.StdoutPipe()
				if err != nil {
					return
				}

				cerr, err := c.StderrPipe()
				if err != nil {
					return
				}

				if err := c.Start(); err != nil {
					fmt.Fprintf(os.Stderr, "harness: exec start: %v\n", err)
					continue
				}

				wmu.Lock()
				cmd = c
				stdin = cin
				wmu.Unlock()

				fmt.Println("INTEROP-GO-SESSION-EXEC")

				// the stdout rides as 94, the stderr as 95 with
				// dataType 1 (docs/P4-WIRE.md 3.1); both pumps must
				// drain before the exit-status goes out, otherwise the
				// client stops reading at the verdict and loses the
				// command output tail
				var pumps sync.WaitGroup

				pumps.Add(2)

				go func() {
					defer pumps.Done()
					s3PumpToChannel(str, &wmu, cout, false)
				}()

				go func() {
					defer pumps.Done()
					s3PumpToChannel(str, &wmu, cerr, true)
				}()

				go func() {
					pumps.Wait() // the pipes hit EOF, Wait() is safe now

					code := s3ExitCode(c)

					frame := s3AppendVarint(nil, 98)
					frame = s3AppendSSHString(frame, []byte("exit-status"))
					frame = append(frame, 0) // want_reply = 0
					frame = s3AppendVarint(frame, code)

					wmu.Lock()
					_, _ = str.Write(frame)
					wmu.Unlock()

					fmt.Printf("INTEROP-GO-SESSION-EXIT code=%d\n", code)

					_ = str.Close() // the channel FIN, like channel.Close()
				}()

			case "signal":
				name, err := s3ReadSSHString(br)
				if err != nil {
					return
				}

				wmu.Lock()
				c := cmd
				wmu.Unlock()

				if c == nil || c.Process == nil {
					continue // no process: the request is ignored
				}

				switch string(name) {
				case "KILL":
					_ = c.Process.Kill()
				case "TERM":
					_ = c.Process.Signal(syscall.SIGTERM)
				default:
					// unknown names are ignored, like the reference
				}
			case "exit-status":
				// the server never receives one; the body is one varint
				if _, err := s3ReadVarint(br); err != nil {
					return
				}
			default:
				// an unknown request type: its body has no length
				// prefix on the wire, the message flow is unsynced
				// from here (the reference cancels such a channel)
				str.CancelRead(42)
				str.CancelWrite(42)
				return
			}

		default:
			str.CancelRead(42)
			str.CancelWrite(42)
			return
		}
	}
}

// s3PumpToChannel forwards one process output pipe to the channel as
// 94 (stdout) or 95 with dataType 1 (stderr) frames; one frame per
// read chunk, 16 KiB is far below the 30000 maxPacketSize
func s3PumpToChannel(str *quic.Stream, mu *sync.Mutex, r io.Reader, extended bool) {
	buf := make([]byte, 16384)

	for {
		n, err := r.Read(buf)

		if n > 0 {
			var frame []byte

			if extended {
				frame = s3AppendVarint(nil, 95)
				frame = s3AppendVarint(frame, 1)
			} else {
				frame = s3AppendVarint(nil, 94)
			}

			frame = s3AppendSSHString(frame, buf[:n])

			mu.Lock()
			_, werr := str.Write(frame)
			mu.Unlock()

			if werr != nil {
				return
			}
		}

		if err != nil {
			return
		}
	}
}

// s3ExitCode maps the command result to the exit-status code: a
// process killed by a signal reports 128+signum (137 for SIGKILL,
// 143 for SIGTERM), like the ssh3-c session server reaps it
func s3ExitCode(c *exec.Cmd) uint64 {
	err := c.Wait()

	if err == nil {
		return 0
	}

	var ee *exec.ExitError

	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + uint64(ws.Signal())
		}

		return uint64(ee.ExitCode())
	}

	return 1
}

// runH3SessionClient dials, opens the extended CONNECT and then one
// ssh3 session channel: the exec request runs -cmd with the fin right
// behind it and the verdict is the 98 exit-status (zero plus the
// s3-exec-ok marker in the output).  With -kill the client keeps the
// stream writable, signals KILL right after the 91 confirmation and
// expects the exit-status 137 (128 + SIGKILL)
func runH3SessionClient(target string, timeout time.Duration, command string, kill bool) {
	if target == "" {
		fatalf("h3-session-client mode needs -a host:port")
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

	// the extended CONNECT opens the conversation control stream, the
	// low-level API like in runH3Client (RFC 9220)
	cc := (&http3.Transport{}).NewClientConn(conn)

	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		fatalf("open request stream: %v", err)
	}

	req, err := http.NewRequest(http.MethodConnect, "https://"+target+"/ssh3-term", nil)
	if err != nil {
		fatalf("build connect request: %v", err)
	}

	req.Proto = "ssh3"
	req.Header.Set("User-Agent", s3VersionString)
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

	// the channel: a fresh bidi stream, the header quotes the control
	// stream id (ChannelID == StreamID, docs/P4-WIRE.md 2)
	ch, err := conn.OpenStream()
	if err != nil {
		fatalf("open channel stream: %v", err)
	}

	if err := ch.SetDeadline(time.Now().Add(timeout)); err != nil {
		fatalf("set channel deadline: %v", err)
	}

	header := s3AppendVarint(nil, s3SSHFrameType)
	header = s3AppendVarint(header, uint64(str.StreamID()))
	header = s3AppendSSHString(header, []byte("session"))
	header = s3AppendVarint(header, s3ChannelMaxPacket)

	execReq := s3AppendVarint(nil, 98)
	execReq = s3AppendSSHString(execReq, []byte("exec"))
	execReq = append(execReq, 1) // want_reply = 1
	execReq = s3AppendSSHString(execReq, []byte(command))

	if _, err := ch.Write(append(header, execReq...)); err != nil {
		fatalf("write channel: %v", err)
	}

	if !kill {
		// the exec carries no stdin: the fin goes out at once (Close
		// is the half-close of quic-go, the receive side stays
		// open); the kill run keeps the stream writable for the
		// signal request
		if err := ch.Close(); err != nil {
			fatalf("close channel: %v", err)
		}
	}

	br := bufio.NewReader(ch)

	var out []byte

	first := true

	for {
		typ, err := s3ReadVarint(br)
		if err != nil {
			fatalf("channel read: %v", err)
		}

		if first {
			// the 91 confirmation must be the first channel message
			if typ != 91 {
				fatalf("expected the 91 confirmation, got %d", typ)
			}

			if _, err := s3ReadVarint(br); err != nil { // maxPacketSize
				fatalf("read confirmation: %v", err)
			}

			first = false

			if kill {
				sig := s3AppendVarint(nil, 98)
				sig = s3AppendSSHString(sig, []byte("signal"))
				sig = append(sig, 0) // want_reply = 0
				sig = s3AppendSSHString(sig, []byte("KILL"))

				if _, err := ch.Write(sig); err != nil {
					fatalf("send signal: %v", err)
				}
			}

			continue
		}

		switch typ {
		case 94: // SSH_MSG_CHANNEL_DATA: the stdout accumulates
			data, err := s3ReadSSHString(br)
			if err != nil {
				fatalf("read data: %v", err)
			}

			out = append(out, data...)

		case 95: // SSH_MSG_CHANNEL_EXTENDED_DATA: drained
			if _, err := s3ReadVarint(br); err != nil { // data type
				fatalf("read extended data: %v", err)
			}

			if _, err := s3ReadSSHString(br); err != nil {
				fatalf("read extended data: %v", err)
			}

		case 98: // SSH_MSG_CHANNEL_REQUEST: the verdict carrier
			rtype, err := s3ReadSSHString(br)
			if err != nil {
				fatalf("read request: %v", err)
			}

			var wantReply [1]byte

			if _, err := io.ReadFull(br, wantReply[:]); err != nil {
				fatalf("read request: %v", err)
			}

			if string(rtype) != "exit-status" {
				fatalf("unexpected request %q", rtype)
			}

			code, err := s3ReadVarint(br)
			if err != nil {
				fatalf("read exit status: %v", err)
			}

			if kill {
				if code == 137 {
					fmt.Println("INTEROP-GO-KILL-OK exit=137")
					return
				}

				fmt.Printf("INTEROP-GO-KILL-FAIL exit=%d\n", code)
				os.Exit(1)
			}

			if code == 0 && bytes.Contains(out, []byte("s3-exec-ok")) {
				fmt.Println("INTEROP-GO-EXEC-OK exit=0")
				return
			}

			fmt.Printf("INTEROP-GO-EXEC-FAIL exit=%d\n", code)
			os.Exit(1)

		default:
			fatalf("unexpected channel message %d", typ)
		}
	}
}
