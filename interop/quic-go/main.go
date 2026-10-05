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
//	harness -h3-forward-server -addr 127.0.0.1:4433 -cert cert.pem -key key.pem
//	harness -h3-forward-client -a 127.0.0.1:4433 -fwd-tcp 13456/127.0.0.1@19999
//	harness -h3-sftp-server -addr 127.0.0.1:4433 -cert cert.pem -key key.pem
//	harness -h3-sftp-client -a 127.0.0.1:4433 -sftp-op put:./local.bin:remote.bin
//	harness -h3-agent-server -addr 127.0.0.1:4433 -cert cert.pem -key key.pem
//	harness -h3-agent-client -a 127.0.0.1:4433 [-cmd 'printf s3-exec-ok']
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
// The -h3-forward-* modes run the direct-tcp/direct-udp forwarding
// channels (docs/P4-WIRE.md 2.1 with the address extension, 3.2 for
// the datagrams) over the same raw server dispatch: the server dials
// the target carried in the channel header and pipes the socket (94
// frames for TCP, the one QUIC datagram receiver of the connection
// for UDP); the client (-fwd-tcp localport/remoteip@remoteport)
// forwards every accepted connection of its local listener through
// one direct-tcp channel each.  The UDP client side is not
// implemented: only the server side of direct-udp exists here.
//
// The -h3-sftp-* modes run the minimal SFTP v3 subsystem
// (draft-ietf-secsh-filexfer-02) over the "sftp" channel: the server
// jails every path to the home directory with the reference
// resolveJailed semantics and chowns the created inodes back to the
// current user; the client (-sftp-op put|get:local:remote) streams the
// file in 32768-byte chunks and verifies the copy with a sha256
// read-back.
//
// The -h3-agent-* modes run the agent forwarding (the reference LARVAL
// trigger): a 94 data frame "forward-agent" before the exec makes the
// server listen on a temp-dir unix socket (SSH_AUTH_SOCK of the exec
// env) and open one server-initiated "agent-connection" channel per
// accepted connection; the client bridges every such channel to its
// local SSH_AUTH_SOCK.
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
//	INTEROP-GO-FWD-TCP-OPEN target=<host:port>
//	INTEROP-GO-FWD-UDP-OPEN target=<host:port>
//	INTEROP-GO-FWD-LISTEN port=<port>
//	SFTP-GO-SUBSYSTEM-READY home=<jail>
//	SFTP-GO-CLIENT-DONE op=<put|get> bytes=<n>
//	AGENT-GO-SOCKET-READY sock=<path>
//	AGENT-GO-BRIDGE
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
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
	h3ForwardServer := flag.Bool("h3-forward-server", false,
		"HTTP/3 server accepting direct-tcp/direct-udp forwarding channels")
	h3ForwardClient := flag.Bool("h3-forward-client", false,
		"HTTP/3 client forwarding a local TCP listener through a direct-tcp channel")
	fwdTCP := flag.String("fwd-tcp", "",
		"h3-forward-client: localport/remoteip@remoteport, e.g. 13456/127.0.0.1@19999")
	h3SFTPServer := flag.Bool("h3-sftp-server", false,
		"HTTP/3 server serving the minimal SFTP v3 subsystem over \"sftp\" channels")
	h3SFTPClient := flag.Bool("h3-sftp-client", false,
		"HTTP/3 client running a minimal SFTP v3 put/get over an \"sftp\" channel")
	sftpOp := flag.String("sftp-op", "",
		"h3-sftp-client: put|get:local:remote, e.g. put:./data.bin:remote.bin")
	h3AgentServer := flag.Bool("h3-agent-server", false,
		"HTTP/3 server with session channels and the forward-agent LARVAL trigger")
	h3AgentClient := flag.Bool("h3-agent-client", false,
		"HTTP/3 client running the session exec plus the agent bridge")
	flag.Parse()

	if !*streams && *size > 1100 {
		// the datagram must fit the 1200 byte max_datagram_frame_size
		// advertised by the ssh3-c runners with a frame header on top
		*size = 1100
	}

	modes := 0
	for _, m := range []*bool{server, client, h3Server, h3Client, h3SessionServer,
		h3SessionClient, h3ForwardServer, h3ForwardClient,
		h3SFTPServer, h3SFTPClient, h3AgentServer, h3AgentClient} {
		if *m {
			modes++
		}
	}
	if modes > 1 {
		fatalf("-server, -client, -h3-server, -h3-client, -h3-session-server, " +
			"-h3-session-client, -h3-forward-server, -h3-forward-client, " +
			"-h3-sftp-server, -h3-sftp-client, -h3-agent-server and -h3-agent-client " +
			"are mutually exclusive")
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

	if *h3SFTPServer {
		runH3SFTPServer(*addr, *certFile, *keyFile)
		return
	}

	if *h3AgentServer {
		runH3AgentServer(*addr, *certFile, *keyFile)
		return
	}

	if *h3ForwardServer {
		runH3ForwardServer(*addr, *certFile, *keyFile)
		return
	}

	if *h3ForwardClient {
		target := *addr
		if *addrShort != "" {
			target = *addrShort
		}
		runH3ForwardClient(target, *fwdTCP, *timeout)
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

	if *h3SFTPClient {
		target := *addr
		if *addrShort != "" {
			target = *addrShort
		}
		runH3SFTPClient(target, *sftpOp, *timeout)
		return
	}

	if *h3AgentClient {
		target := *addr
		if *addrShort != "" {
			target = *addrShort
		}
		runH3AgentClient(target, *timeout, *command)
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

// s3RunRawH3Server is the common listener of the channel-flavored h3
// modes (session, sftp, agent): the RFC 9220 extended CONNECT is
// answered through the http3 stack (the same h3ConnectHandler as the
// -h3-server mode), the raw bidi dispatch belongs to the serve
// callback (http3.Server.NewRawServerConn keeps it here: the plain
// http3.Server accept loop parses every bidi as an HTTP request)
func s3RunRawH3Server(addr, certFile, keyFile, mode string,
	serve func(*http3.Server, *quic.Conn),
) {
	if certFile == "" || keyFile == "" {
		fatalf("%s mode needs -cert and -key", mode)
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

		go serve(server, conn)
	}
}

// s3ServeChannels runs one accepted QUIC connection of a channel mode:
// the h3 layer (the peer's control/QPACK uni streams and the CONNECT
// request) is fed through the raw server conn, the first bidi stream
// is the CONNECT (its StreamID is the conversationStreamID the
// channels quote in their headers, docs/P4-WIRE.md 1, the reference
// server dispatch rule) and every later bidi goes to the handler.
// Each channel runs on its own goroutine with per-channel state; the
// harness peers use one channel per connection in practice.
func s3ServeChannels(server *http3.Server, conn *quic.Conn, handle func(*quic.Stream, uint64)) {
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
			convID = uint64(str.StreamID())
			haveConv = true

			go raw.HandleRequestStream(str)
			continue
		}

		go handle(str, convID)
	}
}

// runH3SessionServer serves the ssh3 session scenarios: only exec,
// signal and exit-status requests exist on this server (the PIN:
// wantReply is ignored, the 92/93/96/97/99/100 messages do not exist)
func runH3SessionServer(addr, certFile, keyFile string) {
	s3RunRawH3Server(addr, certFile, keyFile, "h3-session-server", serveSessionConn)
}

func serveSessionConn(server *http3.Server, conn *quic.Conn) {
	s3ServeChannels(server, conn, s3HandleSessionChannel)
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

				c, cin, ok := s3SpawnExec(str, &wmu, string(command), nil)
				if !ok {
					continue
				}

				wmu.Lock()
				cmd = c
				stdin = cin
				wmu.Unlock()

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

// s3SpawnExec starts the sh -c command of an exec request, pumps the
// process output through the channel as 94/95 frames and closes the
// channel behind the 98 exit-status (the docs/P4-WIRE.md 6 flow both
// session flavors share); extraEnv rides the process env.  The command
// and its stdin pipe come back for the signal/stdin handling of the
// caller.
func s3SpawnExec(str *quic.Stream, wmu *sync.Mutex, command string,
	extraEnv []string,
) (*exec.Cmd, io.WriteCloser, bool) {
	c := exec.Command("sh", "-c", command)

	if len(extraEnv) > 0 {
		c.Env = append(os.Environ(), extraEnv...)
	}

	cin, err := c.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "harness: exec stdin pipe: %v\n", err)
		return nil, nil, false
	}

	cout, err := c.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "harness: exec stdout pipe: %v\n", err)
		return nil, nil, false
	}

	cerr, err := c.StderrPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "harness: exec stderr pipe: %v\n", err)
		return nil, nil, false
	}

	if err := c.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "harness: exec start: %v\n", err)
		return nil, nil, false
	}

	fmt.Println("INTEROP-GO-SESSION-EXEC")

	// the stdout rides as 94, the stderr as 95 with dataType 1
	// (docs/P4-WIRE.md 3.1); both pumps must drain before the
	// exit-status goes out, otherwise the client stops reading at the
	// verdict and loses the command output tail
	var pumps sync.WaitGroup

	pumps.Add(2)

	go func() {
		defer pumps.Done()
		s3PumpToChannel(str, wmu, cout, false)
	}()

	go func() {
		defer pumps.Done()
		s3PumpToChannel(str, wmu, cerr, true)
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

	return c, cin, true
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

// s3DialAndConnect dials the QUIC target, opens the RFC 9220 extended
// CONNECT (the low-level NewClientConn API, the conversation control
// stream) with the harness user-agent and token and returns the
// connection with the request stream once the 200 came back; any other
// status ends the process
func s3DialAndConnect(target string, ctx context.Context,
	timeout time.Duration,
) (*quic.Conn, *http3.RequestStream) {
	tlsCfg := &tls.Config{
		NextProtos:         []string{http3.NextProtoH3},
		InsecureSkipVerify: true, // the harness runs against self-signed certs
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		fatalf("local udp: %v", err)
	}

	tr := &quic.Transport{Conn: udpConn}

	conn, err := tr.Dial(ctx, udpAddr(target), tlsCfg, &quic.Config{
		MaxIdleTimeout: 60 * time.Second,
	})
	if err != nil {
		fatalf("dial: %v", err)
	}

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

	return conn, str
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

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, str := s3DialAndConnect(target, ctx, timeout)
	defer conn.CloseWithError(0, "")

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

	code, out := s3SessionExecRead(ch, kill)

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
}

// s3SessionExecRead consumes the channel messages of one exec session:
// the 91 confirmation must come first (the -kill run signals KILL
// right behind it), then the 94/95 output accumulates until the 98
// exit-status verdict arrives
func s3SessionExecRead(ch *quic.Stream, kill bool) (uint64, []byte) {
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

			_ = wantReply

			if string(rtype) != "exit-status" {
				fatalf("unexpected request %q", rtype)
			}

			code, err := s3ReadVarint(br)
			if err != nil {
				fatalf("read exit status: %v", err)
			}

			return code, out

		default:
			fatalf("unexpected channel message %d", typ)
		}
	}
}

// s3ForwardServer holds the forwarding state of one accepted QUIC
// connection: the conversation id (the datagram prefix and the
// channel header check) and the direct-udp channels.  One UDP channel
// per connection is the exercised scenario, the map supports several
// anyway.
type s3ForwardServer struct {
	conn   *quic.Conn
	convID uint64

	sendMu sync.Mutex // serializes SendDatagram across the UDP pumps

	mu  sync.Mutex
	udp map[quic.StreamID]*net.UDPConn
}

func (fs *s3ForwardServer) addUDPChannel(id quic.StreamID, sock *net.UDPConn) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.udp[id] = sock
}

func (fs *s3ForwardServer) removeUDPChannel(id quic.StreamID) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	delete(fs.udp, id)
}

func (fs *s3ForwardServer) udpChannel(id quic.StreamID) *net.UDPConn {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.udp[id]
}

func (fs *s3ForwardServer) sendDatagram(data []byte) error {
	fs.sendMu.Lock()
	defer fs.sendMu.Unlock()

	return fs.conn.SendDatagram(data)
}

// runH3ForwardServer serves the forwarding scenarios: the RFC 9220
// extended CONNECT rides the same raw server conn as the session
// server (the first bidi stream is the CONNECT, every later bidi is a
// direct-tcp or direct-udp channel), plus the single QUIC datagram
// receiver per connection routes the UDP payloads of the direct-udp
// channels to their dialed targets (docs/P4-WIRE.md 1, 3.2)
func runH3ForwardServer(addr, certFile, keyFile string) {
	if certFile == "" || keyFile == "" {
		fatalf("h3-forward-server mode needs -cert and -key")
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
			MaxIdleTimeout:  60 * time.Second,
			EnableDatagrams: true, // the direct-udp path
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

		go serveForwardConn(server, conn)
	}
}

// serveForwardConn runs one accepted QUIC connection of the forward
// server: the h3 layer is fed through the raw server conn, the first
// bidi is the CONNECT (its StreamID is the conversation) and every
// later bidi is a forwarding channel; the datagram loop starts once
// the conversation id is known
func serveForwardConn(server *http3.Server, conn *quic.Conn) {
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

	fs := &s3ForwardServer{conn: conn, udp: make(map[quic.StreamID]*net.UDPConn)}

	var haveConv bool

	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		if !haveConv {
			// the first bidi stream is the extended CONNECT, its
			// StreamID is the conversationStreamID the channels and
			// the datagrams must quote
			fs.convID = uint64(str.StreamID())
			haveConv = true

			go raw.HandleRequestStream(str)
			go fs.datagramLoop()
			continue
		}

		go s3HandleForwardChannel(str, fs)
	}
}

// datagramLoop is the single QUIC datagram receiver of the connection
// (docs/P4-WIRE.md 3.2): the prefix is varint controlStreamID, varint
// channelID, the rest is the raw UDP payload; foreign conversations
// and unknown channels are dropped without any error on the wire,
// like the reference receive loop does
func (fs *s3ForwardServer) datagramLoop() {
	for {
		data, err := fs.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}

		rd := bytes.NewReader(data)

		conv, err := s3ReadVarint(rd)
		if err != nil || conv != fs.convID {
			continue
		}

		channel, err := s3ReadVarint(rd)
		if err != nil {
			continue
		}

		sock := fs.udpChannel(quic.StreamID(channel))
		if sock == nil {
			continue
		}

		// what is left of the datagram is the raw UDP payload; the
		// socket is connected (DialUDP), so a plain Write goes to the
		// one target of the channel
		if _, err := sock.Write(data[len(data)-rd.Len():]); err != nil {
			continue // the datagram path is lossy by definition
		}
	}
}

// s3HandleForwardChannel runs one accepted forwarding channel: the
// header is the session one plus the address extension
// (docs/P4-WIRE.md 2.1, the reference
// buildForwardingChannelAdditionalBytes).  direct-tcp dials the
// target and pipes the socket through 94 frames, direct-udp dials it
// and registers the socket for the datagram loop; a refused channel
// is cancelled with code 0 like the reference accept loop (the 92
// failure message is never sent)
func s3HandleForwardChannel(str *quic.Stream, fs *s3ForwardServer) {
	br := bufio.NewReader(str)

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

	if ftype != s3SSHFrameType || convid != fs.convID {
		// the reference answer to a bad channel is cancel(0)
		str.CancelRead(0)
		str.CancelWrite(0)
		return
	}

	target, err := s3ReadForwardTarget(br)
	if err != nil {
		str.CancelRead(0)
		str.CancelWrite(0)
		return
	}

	switch string(ctype) {
	case "direct-tcp":
		sock, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "harness: dial tcp %s: %v\n", target, err)
			str.CancelRead(0)
			str.CancelWrite(0)
			return
		}

		// the 91 confirmation with our maxPacketSize, like
		// confirmChannel()
		if _, err := str.Write(s3AppendVarint(s3AppendVarint(nil, 91), s3ChannelMaxPacket)); err != nil {
			sock.Close()
			return
		}

		fmt.Printf("INTEROP-GO-FWD-TCP-OPEN target=%s\n", target)

		s3PipeTCPThroughChannel(str, br, sock)

	case "direct-udp":
		fs.handleUDPChannel(str, target)

	default:
		str.CancelRead(0)
		str.CancelWrite(0)
	}
}

// handleUDPChannel dials the direct-udp target, confirms the channel
// and registers the socket: inbound datagrams of the channel go to
// the target through the datagram loop, the replies ride back as
// controlStreamID/channelID-prefixed datagrams.  The channel stream
// carries no payload, its FIN tears the registration and the socket
// down.
func (fs *s3ForwardServer) handleUDPChannel(str *quic.Stream, target string) {
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		str.CancelRead(0)
		str.CancelWrite(0)
		return
	}

	sock, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "harness: dial udp %s: %v\n", target, err)
		str.CancelRead(0)
		str.CancelWrite(0)
		return
	}

	if _, err := str.Write(s3AppendVarint(s3AppendVarint(nil, 91), s3ChannelMaxPacket)); err != nil {
		sock.Close()
		return
	}

	fmt.Printf("INTEROP-GO-FWD-UDP-OPEN target=%s\n", target)

	id := str.StreamID()

	fs.addUDPChannel(id, sock)

	// the replies of the target ride back as datagrams; one too large
	// for the current path MTU is dropped, it is UDP
	go func() {
		buf := make([]byte, 65535)

		for {
			n, err := sock.Read(buf)
			if err != nil {
				return
			}

			frame := s3AppendVarint(nil, fs.convID)
			frame = s3AppendVarint(frame, uint64(id))
			frame = append(frame, buf[:n]...)

			if err := fs.sendDatagram(frame); err != nil {
				var tooLarge *quic.DatagramTooLargeError
				if errors.As(err, &tooLarge) {
					continue
				}

				return
			}
		}
	}()

	// the peer FIN on the channel stream is the channel close
	_, _ = io.Copy(io.Discard, str)

	fs.removeUDPChannel(id)
	sock.Close()
}

// s3ReadForwardTarget parses the address extension that follows the
// maxPacketSize of the direct and forwarded channel types
// (docs/P4-WIRE.md 2.1): varint addressFamily (4 or 6), the raw IP of
// 4 or 16 bytes, the uint16 big-endian port; it comes back in the
// host:port dial form
func s3ReadForwardTarget(br *bufio.Reader) (string, error) {
	family, err := s3ReadVarint(br)
	if err != nil {
		return "", err
	}

	ipLen := 0

	switch family {
	case 4:
		ipLen = 4
	case 6:
		ipLen = 16
	default:
		return "", fmt.Errorf("bad address family %d", family)
	}

	raw := make([]byte, ipLen)

	if _, err := io.ReadFull(br, raw); err != nil {
		return "", err
	}

	var port [2]byte

	if _, err := io.ReadFull(br, port[:]); err != nil {
		return "", err
	}

	return net.JoinHostPort(net.IP(raw).String(),
		strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

// s3PipeTCPThroughChannel pumps one TCP connection through the
// channel stream in both directions: the socket reads ride as 94
// frames (one per 16 KiB chunk, far below the 30000 maxPacketSize),
// the stream 94 frames go back into the socket.  The socket EOF is
// the stream FIN (the half close), the stream FIN closes the socket;
// anything else than 94 from the peer resets the channel.
func s3PipeTCPThroughChannel(str *quic.Stream, br *bufio.Reader, sock net.Conn) {
	go func() { // socket -> 94 frames
		buf := make([]byte, 16384)

		for {
			n, err := sock.Read(buf)

			if n > 0 {
				frame := s3AppendVarint(nil, 94)
				frame = s3AppendSSHString(frame, buf[:n])

				if _, werr := str.Write(frame); werr != nil {
					sock.Close()
					return
				}
			}

			if err != nil {
				_ = str.Close() // the socket EOF: the stream FIN
				return
			}
		}
	}()

	for { // 94 frames -> socket
		typ, err := s3ReadVarint(br)
		if err != nil {
			// the stream FIN of the client: shutdown the target write
			// side and let the socket goroutine drain the echo tail; a
			// hard close here would RST the connection and lose it

			if tc, ok := sock.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			} else {
				sock.Close()
			}

			return
		}

		if typ != 94 {
			str.CancelRead(0)
			str.CancelWrite(0)
			sock.Close()
			return
		}

		data, err := s3ReadSSHString(br)
		if err != nil {
			sock.Close()
			return
		}

		if _, err := sock.Write(data); err != nil {
			str.CancelRead(0)
			str.CancelWrite(0)
			return
		}
	}
}

// runH3ForwardClient dials, opens the extended CONNECT and then
// forwards a local TCP listener through direct-tcp channels
// (-fwd-tcp localport/remoteip@remoteport): every accepted local
// connection opens one channel (the header quotes the CONNECT stream
// id and carries the raw-IP target), the 91 confirmation arms the
// two-way 94 pipe.  The run lives until SIGINT or the -timeout.  The
// UDP client side does not exist in this harness.
func runH3ForwardClient(target, fwd string, timeout time.Duration) {
	if target == "" {
		fatalf("h3-forward-client mode needs -a host:port")
	}

	if fwd == "" {
		fatalf("h3-forward-client mode needs -fwd-tcp localport/remoteip@remoteport")
	}

	localPort, remotePort, remoteHost, err := s3ParseFwdTCP(fwd)
	if err != nil {
		fatalf("bad -fwd-tcp %q: %v", fwd, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, str := s3DialAndConnect(target, ctx, timeout)
	defer conn.CloseWithError(0, "")

	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
	if err != nil {
		fatalf("listen: %v", err)
	}

	fmt.Printf("INTEROP-GO-FWD-LISTEN port=%d\n", listener.Addr().(*net.TCPAddr).Port)

	// the run ends on SIGINT or the -timeout: both close the
	// listener, the accept loop unwinds and the connection goes with
	// the deferred Close
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		<-sig
		listener.Close()
	}()

	convID := uint64(str.StreamID())

	for {
		local, err := listener.Accept()
		if err != nil {
			return // the listener is closed: the run is over
		}

		go s3OpenDirectTCPChannel(conn, convID, remoteHost, remotePort, timeout, local)
	}
}

// s3ParseFwdTCP parses the -fwd-tcp value in the
// localport/remoteip@remoteport form (e.g. 13456/127.0.0.1@19999);
// the remote target must be an IP: the channel header carries the
// raw address bytes, there are no names on the wire
func s3ParseFwdTCP(fwd string) (localPort, remotePort int, remoteHost string, err error) {
	slash := strings.SplitN(fwd, "/", 2)
	if len(slash) != 2 {
		return 0, 0, "", fmt.Errorf("want localport/remoteip@remoteport")
	}

	if localPort, err = strconv.Atoi(slash[0]); err != nil || localPort < 0 || localPort > 65535 {
		return 0, 0, "", fmt.Errorf("bad local port %q", slash[0])
	}

	at := strings.SplitN(slash[1], "@", 2)
	if len(at) != 2 || at[0] == "" {
		return 0, 0, "", fmt.Errorf("want localport/remoteip@remoteport")
	}

	if net.ParseIP(at[0]) == nil {
		return 0, 0, "", fmt.Errorf("the remote target must be an IP, got %q", at[0])
	}

	if remotePort, err = strconv.Atoi(at[1]); err != nil || remotePort < 1 || remotePort > 65535 {
		return 0, 0, "", fmt.Errorf("bad remote port %q", at[1])
	}

	return localPort, remotePort, at[0], nil
}

// s3OpenDirectTCPChannel opens one direct-tcp channel for an accepted
// local connection: the header quotes the conversation (the CONNECT
// stream id) and carries the target (docs/P4-WIRE.md 2.1), the 91
// confirmation arms the pipe
func s3OpenDirectTCPChannel(conn *quic.Conn, convID uint64, host string, port int,
	timeout time.Duration, local net.Conn,
) {
	str, err := conn.OpenStream()
	if err != nil {
		local.Close()
		return
	}

	ip := net.ParseIP(host)

	family := uint64(4)
	rawIP := ip.To4()

	if rawIP == nil {
		family = 6
		rawIP = ip.To16()
	}

	header := s3AppendVarint(nil, s3SSHFrameType)
	header = s3AppendVarint(header, convID)
	header = s3AppendSSHString(header, []byte("direct-tcp"))
	header = s3AppendVarint(header, s3ChannelMaxPacket)
	header = s3AppendVarint(header, family)
	header = append(header, rawIP...)
	header = append(header, byte(port>>8), byte(port))

	// the deadline guards the handshake only: an established pipe may
	// idle as long as the peers keep it
	if err := str.SetDeadline(time.Now().Add(timeout)); err != nil {
		str.CancelRead(0)
		str.CancelWrite(0)
		local.Close()
		return
	}

	if _, err := str.Write(header); err != nil {
		str.CancelRead(0)
		str.CancelWrite(0)
		local.Close()
		return
	}

	br := bufio.NewReader(str)

	typ, err := s3ReadVarint(br)
	if err != nil || typ != 91 {
		// a refusal (the server cancels instead of 91) or a timeout
		str.CancelRead(0)
		str.CancelWrite(0)
		local.Close()
		return
	}

	if _, err := s3ReadVarint(br); err != nil { // maxPacketSize
		str.CancelRead(0)
		str.CancelWrite(0)
		local.Close()
		return
	}

	if err := str.SetDeadline(time.Time{}); err != nil {
		str.CancelRead(0)
		str.CancelWrite(0)
		local.Close()
		return
	}

	s3PipeTCPThroughChannel(str, br, local)
}

// === SFTP v3 (draft-ietf-secsh-filexfer-02), the -h3-sftp-* modes ===
//
// A minimal request server and client over the "sftp" channel: the
// byte stream the 94 payloads feed carries length-prefixed packets
// (uint32 big-endian length, type byte, [uint32 id,] payload).  The
// server jails every path to the home directory of the current user
// with the reference sftp_subsystem.go resolveJailed semantics and
// chowns the created inodes back to the current uid/gid (a no-op for a
// non-root harness, the reference behavior when it runs as root).

const sftpMaxFrame = 256 * 1024 // the largest frame the server accepts

// SFTP v3 packet types (draft-ietf-secsh-filexfer-02 section 3)
const (
	sftpPktInit     = 1
	sftpPktVersion  = 2
	sftpPktOpen     = 3
	sftpPktClose    = 4
	sftpPktRead     = 5
	sftpPktWrite    = 6
	sftpPktLstat    = 7
	sftpPktSetstat  = 9
	sftpPktFsetstat = 10
	sftpPktOpendir  = 11
	sftpPktReaddir  = 12
	sftpPktRemove   = 13
	sftpPktMkdir    = 14
	sftpPktRmdir    = 15
	sftpPktRealpath = 16
	sftpPktStat     = 17
	sftpPktRename   = 18
	sftpPktStatus   = 101
	sftpPktHandle   = 102
	sftpPktData     = 103
	sftpPktName     = 104
	sftpPktAttrs    = 105
	sftpPktExtended = 200
)

// SFTP v3 status codes
const (
	sftpFxOK               = 0
	sftpFxEOF              = 1
	sftpFxNoSuchFile       = 2
	sftpFxPermissionDenied = 3
	sftpFxFailure          = 4
	sftpFxBadMessage       = 5
	sftpFxOpUnsupported    = 8
)

// SFTP v3 OPEN pflags (SSH_FXF_*)
const (
	sftpFlagRead   = 0x00000001
	sftpFlagWrite  = 0x00000002
	sftpFlagCreate = 0x00000008
	sftpFlagTrunc  = 0x00000010
)

// SFTP v3 attribute flags; the server reports SIZE|PERMISSIONS|ACMODTIME
const (
	sftpAttrSize      = 0x00000001
	sftpAttrUIDGID    = 0x00000002
	sftpAttrPerms     = 0x00000004
	sftpAttrACModTime = 0x00000008
	sftpAttrExtended  = 0x80000000
)

func sftpAppendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func sftpAppendU64(b []byte, v uint64) []byte {
	return append(b, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func sftpAppendStr(b []byte, s string) []byte {
	b = sftpAppendU32(b, uint32(len(s)))
	return append(b, s...)
}

// sftpBody walks the payload of one SFTP packet
type sftpBody struct{ b []byte }

func (r *sftpBody) u32() (uint32, error) {
	if len(r.b) < 4 {
		return 0, errors.New("sftp packet truncated")
	}

	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]

	return v, nil
}

func (r *sftpBody) u64() (uint64, error) {
	if len(r.b) < 8 {
		return 0, errors.New("sftp packet truncated")
	}

	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]

	return v, nil
}

func (r *sftpBody) str() (string, error) {
	n, err := r.u32()
	if err != nil {
		return "", err
	}

	if uint64(len(r.b)) < uint64(n) {
		return "", errors.New("sftp packet truncated")
	}

	s := string(r.b[:n])
	r.b = r.b[n:]

	return s, nil
}

// s3SFTPFrameReader reassembles the length-prefixed SFTP frames out of
// the raw byte stream the channel 94 payloads feed
type s3SFTPFrameReader struct {
	buf []byte
}

// next returns one complete frame; ok=false means more bytes are
// needed, an error means the framing is broken (the channel closes)
func (fr *s3SFTPFrameReader) next() (typ byte, body []byte, ok bool, err error) {
	if len(fr.buf) < 5 {
		return 0, nil, false, nil
	}

	n := binary.BigEndian.Uint32(fr.buf[:4])
	if n < 1 || n > sftpMaxFrame {
		return 0, nil, false, fmt.Errorf("sftp frame length %d out of bounds", n)
	}

	if uint64(len(fr.buf)) < 4+uint64(n) {
		return 0, nil, false, nil
	}

	typ = fr.buf[4]
	body = fr.buf[5 : 4+n]
	fr.buf = fr.buf[4+n:]

	return typ, body, true, nil
}

// sftpErrCode maps an OS error to the SFTP status code
func sftpErrCode(err error) uint32 {
	if errors.Is(err, os.ErrNotExist) {
		return sftpFxNoSuchFile
	}

	if errors.Is(err, os.ErrPermission) {
		return sftpFxPermissionDenied
	}

	return sftpFxFailure
}

// sftpHandleBytes is the 8-byte big-endian form of one handle value
func sftpHandleBytes(h uint64) string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, h)
	return string(b)
}

// sftpHandleValue parses the 8-byte handle back
func sftpHandleValue(h string) (uint64, bool) {
	if len(h) != 8 {
		return 0, false
	}

	return binary.BigEndian.Uint64([]byte(h)), true
}

// sftpAppendAttrs encodes SIZE|PERMISSIONS|ACMODTIME out of a FileInfo
// (the POSIX file type bits ride the permission word)
func sftpAppendAttrs(b []byte, fi fs.FileInfo) []byte {
	b = sftpAppendU32(b, sftpAttrSize|sftpAttrPerms|sftpAttrACModTime)
	b = sftpAppendU64(b, uint64(fi.Size()))

	mode := fi.Mode()
	perms := uint32(mode.Perm())

	switch {
	case mode.IsDir():
		perms |= 0x4000 // S_IFDIR
	case mode&fs.ModeSymlink != 0:
		perms |= 0xA000 // S_IFLNK
	default:
		perms |= 0x8000 // S_IFREG
	}

	b = sftpAppendU32(b, perms)

	mtime := fi.ModTime().Unix()
	b = sftpAppendU32(b, uint32(mtime)) // atime
	b = sftpAppendU32(b, uint32(mtime)) // mtime

	return b
}

// sftpLongname renders the ls-like longname of one directory entry
// (any string is legal on the wire, the ls shape keeps the C peers
// parsing it the same way)
func sftpLongname(name string, fi fs.FileInfo) string {
	kind := byte('-')

	if fi.IsDir() {
		kind = 'd'
	}

	perm := fi.Mode().Perm()

	ls := make([]byte, 9)
	mask := uint32(0400)

	for i := 0; i < 9; i++ {
		if uint32(perm)&mask != 0 {
			ls[i] = "rwxrwxrwx"[i]
		} else {
			ls[i] = '-'
		}

		mask >>= 1
	}

	return fmt.Sprintf("%c%s 1 0 0 %d %s", kind, ls, fi.Size(), name)
}

// sftpDirHandle holds the entries of one open directory: the first
// READDIR carries them all in one NAME, the next ones answer EOF
type sftpDirHandle struct {
	infos []fs.FileInfo
	sent  bool
}

// sftpServer is the request server of one "sftp" channel: the jail
// root, the open file and directory handles, the maxPacketSize the
// peer announced in the channel header (one DATA reply never exceeds
// it) and the write mutex of the channel stream
type sftpServer struct {
	str *quic.Stream
	wmu *sync.Mutex

	root    string
	uid     int
	gid     int
	peerMax uint64

	files map[uint64]*os.File
	dirs  map[uint64]*sftpDirHandle
	next  uint64
}

// s3HandleSFTPChannel runs one accepted "sftp" channel: after the
// header check and the 91 confirmation the SFTP request loop drives
// until the peer closes the channel or a broken frame arrives
func s3HandleSFTPChannel(str *quic.Stream, convID uint64) {
	br := bufio.NewReader(str)

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

	peerMax, err := s3ReadVarint(br) // maxPacketSize
	if err != nil {
		return
	}

	if ftype != s3SSHFrameType || convid != convID || string(ctype) != "sftp" {
		// the reference answer to a bad channel is cancel(0)
		str.CancelRead(0)
		str.CancelWrite(0)
		return
	}

	// the 91 confirmation with our maxPacketSize, like confirmChannel()
	if _, err := str.Write(s3AppendVarint(s3AppendVarint(nil, 91), s3ChannelMaxPacket)); err != nil {
		return
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "harness: sftp: no home directory: %v\n", err)
		str.CancelRead(0)
		str.CancelWrite(0)
		return
	}

	root, err := filepath.Abs(home)
	if err != nil {
		root = home
	}

	fmt.Printf("SFTP-GO-SUBSYSTEM-READY home=%s\n", root)

	s := &sftpServer{
		str:     str,
		wmu:     &sync.Mutex{},
		root:    root,
		uid:     os.Getuid(),
		gid:     os.Getgid(),
		peerMax: peerMax,
		files:   make(map[uint64]*os.File),
		dirs:    make(map[uint64]*sftpDirHandle),
	}
	defer s.closeAll()

	fr := &s3SFTPFrameReader{}

	for {
		typ, err := s3ReadVarint(br)
		if err != nil {
			return // the channel is over
		}

		switch typ {
		case 94: // SSH_MSG_CHANNEL_DATA: the sftp byte stream
			data, err := s3ReadSSHString(br)
			if err != nil {
				return
			}

			fr.buf = append(fr.buf, data...)

			for {
				ptyp, pbody, ok, perr := fr.next()
				if perr != nil {
					// a crooked frame: the channel goes away
					fmt.Fprintf(os.Stderr, "harness: sftp: %v\n", perr)
					str.CancelRead(0)
					str.CancelWrite(0)
					return
				}

				if !ok {
					break
				}

				if !s.dispatch(ptyp, pbody) {
					str.CancelRead(0)
					str.CancelWrite(0)
					return
				}
			}

		case 95: // SSH_MSG_CHANNEL_EXTENDED_DATA: drained
			if _, err := s3ReadVarint(br); err != nil { // data type
				return
			}

			if _, err := s3ReadSSHString(br); err != nil {
				return
			}

		case 98: // SSH_MSG_CHANNEL_REQUEST: nothing but exit-status here
			rtype, err := s3ReadSSHString(br)
			if err != nil {
				return
			}

			var wantReply [1]byte

			if _, err := io.ReadFull(br, wantReply[:]); err != nil {
				return
			}

			_ = wantReply

			if string(rtype) != "exit-status" {
				str.CancelRead(42)
				str.CancelWrite(42)
				return
			}

			if _, err := s3ReadVarint(br); err != nil {
				return
			}

		default:
			str.CancelRead(42)
			str.CancelWrite(42)
			return
		}
	}
}

func (s *sftpServer) closeAll() {
	for h, f := range s.files {
		delete(s.files, h)
		_ = f.Close()
	}
}

// send writes one SFTP packet to the channel as a 94 frame; the uint32
// big-endian length prefix of the packet is added here, pkt carries
// the type byte with the payload
func (s *sftpServer) send(pkt []byte) bool {
	full := make([]byte, 4, 4+len(pkt))
	binary.BigEndian.PutUint32(full, uint32(len(pkt)))
	full = append(full, pkt...)

	frame := s3AppendVarint(nil, 94)
	frame = s3AppendSSHString(frame, full)

	s.wmu.Lock()
	_, err := s.str.Write(frame)
	s.wmu.Unlock()

	return err == nil
}

func (s *sftpServer) status(id, code uint32, msg string) bool {
	pkt := []byte{sftpPktStatus}
	pkt = sftpAppendU32(pkt, id)
	pkt = sftpAppendU32(pkt, code)
	pkt = sftpAppendStr(pkt, msg)
	pkt = sftpAppendStr(pkt, "en")

	return s.send(pkt)
}

func (s *sftpServer) ok(id uint32) bool {
	return s.status(id, sftpFxOK, "ok")
}

func (s *sftpServer) unsupported(id uint32) bool {
	return s.status(id, sftpFxOpUnsupported, "operation unsupported")
}

func (s *sftpServer) sendHandle(id uint32, h uint64) bool {
	pkt := []byte{sftpPktHandle}
	pkt = sftpAppendU32(pkt, id)
	pkt = sftpAppendStr(pkt, sftpHandleBytes(h))

	return s.send(pkt)
}

func (s *sftpServer) newHandle() uint64 {
	s.next++
	return s.next
}

// resolveJailed maps a client-visible path into the jail with the
// reference sftp_subsystem.go semantics: jail-relative paths
// ("docs/f", "/docs/f") resolve under the home directory, absolute
// paths already inside the jail are honored as-is, everything else is
// an escape error (SSH_FX_PERMISSION_DENIED for the client)
func (s *sftpServer) resolveJailed(clientPath string) (string, error) {
	trimmed := strings.TrimSpace(clientPath)
	if trimmed == "" {
		trimmed = "/"
	}

	if filepath.IsAbs(filepath.FromSlash(trimmed)) {
		abs := filepath.Clean(filepath.FromSlash(trimmed))
		if abs == s.root || strings.HasPrefix(abs, s.root+string(filepath.Separator)) {
			return abs, nil
		}
	}

	clean := path.Clean("/" + trimmed)
	full := filepath.Join(s.root, filepath.FromSlash(clean))
	if full != s.root && !strings.HasPrefix(full, s.root+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the home directory", clientPath)
	}

	return full, nil
}

// chownToUser gives a freshly created inode back to the current user
func (s *sftpServer) chownToUser(name string) {
	_ = os.Chown(name, s.uid, s.gid)
}

// chownToUserRoot fixes the freshly created directories under the jail
// (MkdirAll may create more than one level), like the reference
func (s *sftpServer) chownToUserRoot(name string) {
	for cur := name; cur != s.root && strings.HasPrefix(cur, s.root+string(filepath.Separator)); cur = filepath.Dir(cur) {
		s.chownToUser(cur)
	}
}

// readChunk bounds one DATA payload: the request length, the frame cap
// and the maxPacketSize the peer announced in the channel header
func (s *sftpServer) readChunk() int {
	limit := 32768

	if s.peerMax > 512 && s.peerMax-512 < uint64(limit) {
		limit = int(s.peerMax - 512)
	}

	return limit
}

// dispatch runs one SFTP request; false means the channel must close
// (a write error or a packet type that cannot be answered)
func (s *sftpServer) dispatch(typ byte, body []byte) bool {
	switch typ {
	case sftpPktInit:
		// the only version this harness speaks
		return s.send(append([]byte{sftpPktVersion}, 0, 0, 0, 3))

	case sftpPktOpen:
		r := &sftpBody{body}

		id, err := r.u32()
		if err != nil {
			return false
		}

		pth, err := r.str()
		if err != nil {
			return false
		}

		pflags, err := r.u32()
		if err != nil {
			return false
		}

		return s.open(id, pth, pflags)

	case sftpPktClose:
		r := &sftpBody{body}

		id, err := r.u32()
		if err != nil {
			return false
		}

		handle, err := r.str()
		if err != nil {
			return false
		}

		h, ok := sftpHandleValue(handle)
		if !ok {
			return s.status(id, sftpFxFailure, "bad handle")
		}

		if f, open := s.files[h]; open {
			delete(s.files, h)
			_ = f.Close()
		}
		delete(s.dirs, h)

		return s.ok(id)

	case sftpPktRead:
		r := &sftpBody{body}

		id, err := r.u32()
		if err != nil {
			return false
		}

		handle, err := r.str()
		if err != nil {
			return false
		}

		offset, err := r.u64()
		if err != nil {
			return false
		}

		length, err := r.u32()
		if err != nil {
			return false
		}

		return s.read(id, handle, offset, length)

	case sftpPktWrite:
		r := &sftpBody{body}

		id, err := r.u32()
		if err != nil {
			return false
		}

		handle, err := r.str()
		if err != nil {
			return false
		}

		offset, err := r.u64()
		if err != nil {
			return false
		}

		data, err := r.str()
		if err != nil {
			return false
		}

		return s.write(id, handle, offset, data)

	case sftpPktLstat, sftpPktStat:
		r := &sftpBody{body}

		id, err := r.u32()
		if err != nil {
			return false
		}

		pth, err := r.str()
		if err != nil {
			return false
		}

		return s.statPath(id, pth, typ == sftpPktLstat)

	case sftpPktOpendir:
		r := &sftpBody{body}

		id, err := r.u32()
		if err != nil {
			return false
		}

		pth, err := r.str()
		if err != nil {
			return false
		}

		return s.opendir(id, pth)

	case sftpPktReaddir:
		r := &sftpBody{body}

		id, err := r.u32()
		if err != nil {
			return false
		}

		handle, err := r.str()
		if err != nil {
			return false
		}

		return s.readdir(id, handle)

	case sftpPktRemove, sftpPktRmdir:
		r := &sftpBody{body}

		id, err := r.u32()
		if err != nil {
			return false
		}

		pth, err := r.str()
		if err != nil {
			return false
		}

		return s.removePath(id, pth)

	case sftpPktMkdir:
		r := &sftpBody{body}

		id, err := r.u32()
		if err != nil {
			return false
		}

		pth, err := r.str()
		if err != nil {
			return false
		}

		// the attrs field is ignored, like the reference
		return s.mkdir(id, pth)

	case sftpPktRealpath:
		r := &sftpBody{body}

		id, err := r.u32()
		if err != nil {
			return false
		}

		pth, err := r.str()
		if err != nil {
			return false
		}

		return s.realpath(id, pth)

	case sftpPktRename:
		r := &sftpBody{body}

		id, err := r.u32()
		if err != nil {
			return false
		}

		oldPath, err := r.str()
		if err != nil {
			return false
		}

		newPath, err := r.str()
		if err != nil {
			return false
		}

		return s.rename(id, oldPath, newPath)

	case sftpPktSetstat, sftpPktFsetstat, sftpPktExtended:
		// the raw attribute blobs and the extended requests stay
		// unsupported until needed, like the reference Filecmd default
		var id uint32

		if len(body) >= 4 {
			id = binary.BigEndian.Uint32(body)
		}

		return s.unsupported(id)

	default:
		// server-side reply types and anything unknown: the request
		// flow cannot continue
		return false
	}
}

func (s *sftpServer) open(id uint32, pth string, pflags uint32) bool {
	resolved, err := s.resolveJailed(pth)
	if err != nil {
		return s.status(id, sftpFxPermissionDenied, err.Error())
	}

	flags := os.O_RDONLY

	if pflags&sftpFlagWrite != 0 {
		if pflags&sftpFlagRead != 0 {
			flags = os.O_RDWR
		} else {
			flags = os.O_WRONLY
		}
	}

	if pflags&sftpFlagCreate != 0 {
		flags |= os.O_CREATE
	}

	if pflags&sftpFlagTrunc != 0 {
		flags |= os.O_TRUNC
	}

	f, err := os.OpenFile(resolved, flags, 0o644)
	if err != nil {
		return s.status(id, sftpErrCode(err), err.Error())
	}

	if flags&os.O_CREATE != 0 {
		s.chownToUser(resolved)
	}

	h := s.newHandle()
	s.files[h] = f

	return s.sendHandle(id, h)
}

func (s *sftpServer) read(id uint32, handle string, offset uint64, length uint32) bool {
	h, ok := sftpHandleValue(handle)
	if !ok {
		return s.status(id, sftpFxFailure, "bad handle")
	}

	f, open := s.files[h]
	if !open {
		return s.status(id, sftpFxFailure, "bad handle")
	}

	chunk := int(length)
	if chunk > s.readChunk() {
		chunk = s.readChunk()
	}

	buf := make([]byte, chunk)

	n, err := f.ReadAt(buf, int64(offset))
	if n > 0 {
		pkt := []byte{sftpPktData}
		pkt = sftpAppendU32(pkt, id)
		pkt = sftpAppendStr(pkt, string(buf[:n]))

		return s.send(pkt)
	}

	if err != nil && !errors.Is(err, io.EOF) {
		return s.status(id, sftpErrCode(err), err.Error())
	}

	return s.status(id, sftpFxEOF, "end of file")
}

func (s *sftpServer) write(id uint32, handle string, offset uint64, data string) bool {
	h, ok := sftpHandleValue(handle)
	if !ok {
		return s.status(id, sftpFxFailure, "bad handle")
	}

	f, open := s.files[h]
	if !open {
		return s.status(id, sftpFxFailure, "bad handle")
	}

	if _, err := f.WriteAt([]byte(data), int64(offset)); err != nil {
		return s.status(id, sftpErrCode(err), err.Error())
	}

	return s.ok(id)
}

func (s *sftpServer) statPath(id uint32, pth string, lstat bool) bool {
	resolved, err := s.resolveJailed(pth)
	if err != nil {
		return s.status(id, sftpFxPermissionDenied, err.Error())
	}

	var fi fs.FileInfo

	if lstat {
		fi, err = os.Lstat(resolved)
	} else {
		fi, err = os.Stat(resolved)
	}

	if err != nil {
		return s.status(id, sftpErrCode(err), err.Error())
	}

	pkt := []byte{sftpPktAttrs}
	pkt = sftpAppendU32(pkt, id)
	pkt = sftpAppendAttrs(pkt, fi)

	return s.send(pkt)
}

func (s *sftpServer) opendir(id uint32, pth string) bool {
	resolved, err := s.resolveJailed(pth)
	if err != nil {
		return s.status(id, sftpFxPermissionDenied, err.Error())
	}

	entries, err := os.ReadDir(resolved)
	if err != nil {
		return s.status(id, sftpErrCode(err), err.Error())
	}

	dh := &sftpDirHandle{}

	for _, entry := range entries {
		info, ierr := entry.Info()
		if ierr != nil {
			continue // raced away, like the reference lister
		}

		dh.infos = append(dh.infos, info)
	}

	h := s.newHandle()
	s.dirs[h] = dh

	return s.sendHandle(id, h)
}

func (s *sftpServer) readdir(id uint32, handle string) bool {
	h, ok := sftpHandleValue(handle)
	if !ok {
		return s.status(id, sftpFxFailure, "bad handle")
	}

	dh, open := s.dirs[h]
	if !open {
		return s.status(id, sftpFxFailure, "bad handle")
	}

	if dh.sent {
		return s.status(id, sftpFxEOF, "end of directory")
	}

	dh.sent = true

	pkt := []byte{sftpPktName}
	pkt = sftpAppendU32(pkt, id)
	pkt = sftpAppendU32(pkt, uint32(len(dh.infos)))

	for _, info := range dh.infos {
		pkt = sftpAppendStr(pkt, info.Name())
		pkt = sftpAppendStr(pkt, sftpLongname(info.Name(), info))
		pkt = sftpAppendAttrs(pkt, info)
	}

	return s.send(pkt)
}

func (s *sftpServer) removePath(id uint32, pth string) bool {
	resolved, err := s.resolveJailed(pth)
	if err != nil {
		return s.status(id, sftpFxPermissionDenied, err.Error())
	}

	if err := os.Remove(resolved); err != nil {
		return s.status(id, sftpErrCode(err), err.Error())
	}

	return s.ok(id)
}

func (s *sftpServer) mkdir(id uint32, pth string) bool {
	resolved, err := s.resolveJailed(pth)
	if err != nil {
		return s.status(id, sftpFxPermissionDenied, err.Error())
	}

	if err := os.MkdirAll(resolved, 0o755); err != nil {
		return s.status(id, sftpErrCode(err), err.Error())
	}

	s.chownToUserRoot(resolved)

	return s.ok(id)
}

func (s *sftpServer) realpath(id uint32, pth string) bool {
	resolved, err := s.resolveJailed(pth)
	if err != nil {
		return s.status(id, sftpFxPermissionDenied, err.Error())
	}

	pkt := []byte{sftpPktName}
	pkt = sftpAppendU32(pkt, id)
	pkt = sftpAppendU32(pkt, 1)
	pkt = sftpAppendStr(pkt, resolved)
	pkt = sftpAppendStr(pkt, resolved)

	if fi, serr := os.Stat(resolved); serr == nil {
		pkt = sftpAppendAttrs(pkt, fi)
	} else {
		pkt = sftpAppendU32(pkt, 0) // no attributes known yet
	}

	return s.send(pkt)
}

func (s *sftpServer) rename(id uint32, oldPath, newPath string) bool {
	resolvedOld, err := s.resolveJailed(oldPath)
	if err != nil {
		return s.status(id, sftpFxPermissionDenied, err.Error())
	}

	resolvedNew, err := s.resolveJailed(newPath)
	if err != nil {
		return s.status(id, sftpFxPermissionDenied, err.Error())
	}

	if _, err := os.Lstat(resolvedNew); err == nil {
		return s.status(id, sftpFxFailure, "target exists")
	}

	if err := os.Rename(resolvedOld, resolvedNew); err != nil {
		return s.status(id, sftpErrCode(err), err.Error())
	}

	return s.ok(id)
}

// runH3SFTPServer serves the SFTP scenarios: every bidi after the
// CONNECT is expected to be an "sftp" channel
func runH3SFTPServer(addr, certFile, keyFile string) {
	s3RunRawH3Server(addr, certFile, keyFile, "h3-sftp-server", serveSFTPConn)
}

func serveSFTPConn(server *http3.Server, conn *quic.Conn) {
	s3ServeChannels(server, conn, s3HandleSFTPChannel)
}

// s3ParseSFTPOp parses the -sftp-op value in the put|get:local:remote form
func s3ParseSFTPOp(op string) (put bool, local, remote string, err error) {
	parts := strings.SplitN(op, ":", 3)
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return false, "", "", fmt.Errorf("want put|get:local:remote")
	}

	switch parts[0] {
	case "put":
		put = true
	case "get":
		put = false
	default:
		return false, "", "", fmt.Errorf("op must be put or get, got %q", parts[0])
	}

	return put, parts[1], parts[2], nil
}

// sftpClient is the minimal SFTP v3 driver of the "sftp" channel: the
// requests run one at a time (id-matched, one in flight), the replies
// reassemble out of the 94 payload stream
type sftpClient struct {
	str *quic.Stream
	br  *bufio.Reader
	fr  s3SFTPFrameReader
	id  uint32
}

// recv waits for the next complete SFTP packet, pulling the channel
// messages underneath (the 91 confirmations skipped, the 95 drained)
func (c *sftpClient) recv() (byte, []byte, error) {
	for {
		t, b, ok, ferr := c.fr.next()
		if ferr != nil {
			return 0, nil, ferr
		}

		if ok {
			return t, b, nil
		}

		mt, rerr := s3ReadVarint(c.br)
		if rerr != nil {
			return 0, nil, rerr
		}

		switch mt {
		case 91:
			if _, err := s3ReadVarint(c.br); err != nil {
				return 0, nil, err
			}

		case 94:
			data, err := s3ReadSSHString(c.br)
			if err != nil {
				return 0, nil, err
			}

			c.fr.buf = append(c.fr.buf, data...)

		case 95:
			if _, err := s3ReadVarint(c.br); err != nil { // data type
				return 0, nil, err
			}

			if _, err := s3ReadSSHString(c.br); err != nil {
				return 0, nil, err
			}

		default:
			return 0, nil, fmt.Errorf("unexpected channel message %d", mt)
		}
	}
}

// call sends one request (the id is prepended here, the payload is the
// rest of the body) and returns the next reply packet
func (c *sftpClient) call(typ byte, payload []byte) (byte, []byte, error) {
	c.id++

	body := make([]byte, 4, 5+len(payload))
	binary.BigEndian.PutUint32(body, uint32(len(payload)+5))
	body = append(body, typ)
	body = sftpAppendU32(body, c.id)
	body = append(body, payload...)

	frame := s3AppendVarint(nil, 94)
	frame = s3AppendSSHString(frame, body)

	if _, err := c.str.Write(frame); err != nil {
		return 0, nil, err
	}

	return c.recv()
}

// expectReply validates one reply against the pending id: a STATUS in
// place of the wanted type becomes the error
func (c *sftpClient) expectReply(t byte, b []byte, want byte) (*sftpBody, error) {
	r := &sftpBody{b}

	id, err := r.u32()
	if err != nil {
		return nil, err
	}

	if id != c.id {
		return nil, fmt.Errorf("sftp reply id %d, want %d", id, c.id)
	}

	if t == sftpPktStatus {
		code, err := r.u32()
		if err != nil {
			return nil, err
		}

		if code != sftpFxOK {
			return nil, fmt.Errorf("sftp status %d", code)
		}
	}

	if t != want {
		return nil, fmt.Errorf("sftp reply type %d, want %d", t, want)
	}

	return r, nil
}

func (c *sftpClient) callHandle(typ byte, payload []byte) (string, error) {
	t, b, err := c.call(typ, payload)
	if err != nil {
		return "", err
	}

	r, err := c.expectReply(t, b, sftpPktHandle)
	if err != nil {
		return "", err
	}

	return r.str()
}

func (c *sftpClient) callOK(typ byte, payload []byte) error {
	t, b, err := c.call(typ, payload)
	if err != nil {
		return err
	}

	_, err = c.expectReply(t, b, sftpPktStatus)

	return err
}

func (c *sftpClient) callStat(typ byte, payload []byte) (uint64, bool, error) {
	t, b, err := c.call(typ, payload)
	if err != nil {
		return 0, false, err
	}

	r, err := c.expectReply(t, b, sftpPktAttrs)
	if err != nil {
		return 0, false, err
	}

	return sftpParseAttrsSize(r)
}

// callRead consumes one READ reply: either DATA or the STATUS EOF
func (c *sftpClient) callRead(handle string, offset uint64, length uint32) ([]byte, bool, error) {
	t, b, err := c.call(sftpPktRead, sftpReqRead(handle, offset, length))
	if err != nil {
		return nil, false, err
	}

	r := &sftpBody{b}

	id, err := r.u32()
	if err != nil {
		return nil, false, err
	}

	if id != c.id {
		return nil, false, fmt.Errorf("sftp reply id %d, want %d", id, c.id)
	}

	switch t {
	case sftpPktData:
		data, err := r.str()
		return []byte(data), false, err

	case sftpPktStatus:
		code, err := r.u32()
		if err != nil {
			return nil, false, err
		}

		if code == sftpFxEOF {
			return nil, true, nil
		}

		return nil, false, fmt.Errorf("sftp status %d", code)

	default:
		return nil, false, fmt.Errorf("sftp reply type %d", t)
	}
}

func sftpReqOpen(pth string, pflags uint32) []byte {
	b := sftpAppendStr(nil, pth)
	b = sftpAppendU32(b, pflags)

	return sftpAppendU32(b, 0) // empty attrs
}

func sftpReqClose(handle string) []byte {
	return sftpAppendStr(nil, handle)
}

func sftpReqRead(handle string, offset uint64, length uint32) []byte {
	b := sftpAppendStr(nil, handle)
	b = sftpAppendU64(b, offset)

	return sftpAppendU32(b, length)
}

func sftpReqWrite(handle string, offset uint64, data []byte) []byte {
	b := sftpAppendStr(nil, handle)
	b = sftpAppendU64(b, offset)

	return sftpAppendStr(b, string(data))
}

func sftpReqStat(pth string) []byte {
	return sftpAppendStr(nil, pth)
}

// sftpParseAttrsSize pulls the SIZE attribute out of an ATTRS reply
// (the other fields are skipped, the EXTENDED pairs ride the end of
// the self-delimited frame)
func sftpParseAttrsSize(r *sftpBody) (uint64, bool, error) {
	flags, err := r.u32()
	if err != nil {
		return 0, false, err
	}

	var (
		size    uint64
		hasSize bool
	)

	if flags&sftpAttrSize != 0 {
		if size, err = r.u64(); err != nil {
			return 0, false, err
		}

		hasSize = true
	}

	if flags&sftpAttrUIDGID != 0 {
		if _, err = r.u64(); err != nil {
			return 0, false, err
		}
	}

	if flags&sftpAttrPerms != 0 {
		if _, err = r.u32(); err != nil {
			return 0, false, err
		}
	}

	if flags&sftpAttrACModTime != 0 {
		if _, err = r.u64(); err != nil {
			return 0, false, err
		}
	}

	return size, hasSize, nil
}

// s3SHA256File hashes a local file
func s3SHA256File(pth string) ([]byte, error) {
	f, err := os.Open(pth)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// s3SFTPHashRemote reads the whole remote file through a fresh READ
// handle and returns the byte count with the sha256
func s3SFTPHashRemote(c *sftpClient, remote string) (uint64, []byte, error) {
	handle, err := c.callHandle(sftpPktOpen, sftpReqOpen(remote, sftpFlagRead))
	if err != nil {
		return 0, nil, err
	}

	hasher := sha256.New()

	var off uint64

	for {
		data, eof, err := c.callRead(handle, off, 32768)
		if err != nil {
			return 0, nil, err
		}

		if eof {
			break
		}

		if len(data) == 0 {
			return 0, nil, errors.New("empty DATA before the EOF status")
		}

		hasher.Write(data)
		off += uint64(len(data))
	}

	if err := c.callOK(sftpPktClose, sftpReqClose(handle)); err != nil {
		return 0, nil, err
	}

	return off, hasher.Sum(nil), nil
}

// s3RunSFTPPut streams the local file into the remote path in 32768
// WRITE chunks (one request in flight, id-matched), then verifies the
// remote copy with a sha256 read-back before the verdict
func s3RunSFTPPut(c *sftpClient, local, remote string) error {
	src, err := os.Open(local)
	if err != nil {
		return err
	}
	defer src.Close()

	li, err := src.Stat()
	if err != nil {
		return err
	}

	handle, err := c.callHandle(sftpPktOpen,
		sftpReqOpen(remote, sftpFlagWrite|sftpFlagCreate|sftpFlagTrunc))
	if err != nil {
		return err
	}

	buf := make([]byte, 32768)

	var off uint64

	for {
		n, rerr := src.Read(buf)

		if n > 0 {
			if err := c.callOK(sftpPktWrite, sftpReqWrite(handle, off, buf[:n])); err != nil {
				return err
			}

			off += uint64(n)
		}

		if rerr == io.EOF {
			break
		}

		if rerr != nil {
			return rerr
		}
	}

	if err := c.callOK(sftpPktClose, sftpReqClose(handle)); err != nil {
		return err
	}

	want, err := s3SHA256File(local)
	if err != nil {
		return err
	}

	got, sum, err := s3SFTPHashRemote(c, remote)
	if err != nil {
		return err
	}

	if got != uint64(li.Size()) || !bytes.Equal(sum, want) {
		return fmt.Errorf("remote verify mismatch: %d bytes", got)
	}

	fmt.Printf("SFTP-GO-CLIENT-DONE op=put bytes=%d\n", li.Size())

	return nil
}

// s3RunSFTPGet streams the remote file into the local path through
// READ chunks until the EOF status, then verifies the written file
// against the received sha256 (and the STAT size when it was sent)
func s3RunSFTPGet(c *sftpClient, local, remote string) error {
	remoteSize, hasSize, err := c.callStat(sftpPktStat, sftpReqStat(remote))
	if err != nil {
		return err
	}

	handle, err := c.callHandle(sftpPktOpen, sftpReqOpen(remote, sftpFlagRead))
	if err != nil {
		return err
	}

	dst, err := os.Create(local)
	if err != nil {
		return err
	}

	hasher := sha256.New()

	var off uint64

	for {
		data, eof, err := c.callRead(handle, off, 32768)
		if err != nil {
			dst.Close()
			return err
		}

		if eof {
			break
		}

		if len(data) == 0 {
			dst.Close()
			return errors.New("empty DATA before the EOF status")
		}

		if _, err := dst.Write(data); err != nil {
			dst.Close()
			return err
		}

		hasher.Write(data)
		off += uint64(len(data))
	}

	if err := dst.Close(); err != nil {
		return err
	}

	if err := c.callOK(sftpPktClose, sftpReqClose(handle)); err != nil {
		return err
	}

	lsum, err := s3SHA256File(local)
	if err != nil {
		return err
	}

	if hasSize && off != remoteSize {
		return fmt.Errorf("remote size %d, got %d", remoteSize, off)
	}

	if !bytes.Equal(hasher.Sum(nil), lsum) {
		return errors.New("local verify mismatch")
	}

	fmt.Printf("SFTP-GO-CLIENT-DONE op=get bytes=%d\n", off)

	return nil
}

// runH3SFTPClient dials, opens the extended CONNECT and one "sftp"
// channel, then runs the put/get driver of -sftp-op
func runH3SFTPClient(target, op string, timeout time.Duration) {
	if target == "" {
		fatalf("h3-sftp-client mode needs -a host:port")
	}

	if op == "" {
		fatalf("h3-sftp-client mode needs -sftp-op put|get:local:remote")
	}

	put, local, remote, err := s3ParseSFTPOp(op)
	if err != nil {
		fatalf("bad -sftp-op %q: %v", op, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, str := s3DialAndConnect(target, ctx, timeout)
	defer conn.CloseWithError(0, "")

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
	header = s3AppendSSHString(header, []byte("sftp"))
	header = s3AppendVarint(header, s3ChannelMaxPacket)

	// the INIT rides right behind the header: the server parses the
	// header first, answers the 91 and then serves the request stream
	initBody := append([]byte{sftpPktInit}, 0, 0, 0, 3)
	initPkt := sftpAppendU32(nil, uint32(len(initBody)))
	initPkt = append(initPkt, initBody...)

	burst := append(header, s3AppendVarint(nil, 94)...)
	burst = s3AppendSSHString(burst, initPkt)

	if _, err := ch.Write(burst); err != nil {
		fatalf("write channel: %v", err)
	}

	c := &sftpClient{str: ch, br: bufio.NewReader(ch)}

	// the handshake: the 91 confirmation, then the VERSION reply
	typ, err := s3ReadVarint(c.br)
	if err != nil {
		fatalf("channel read: %v", err)
	}

	if typ != 91 {
		fatalf("expected the 91 confirmation, got %d", typ)
	}

	if _, err := s3ReadVarint(c.br); err != nil { // maxPacketSize
		fatalf("read confirmation: %v", err)
	}

	t, b, err := c.recv()
	if err != nil {
		fatalf("read version: %v", err)
	}

	if t != sftpPktVersion {
		fatalf("expected the sftp VERSION, got %d", t)
	}

	vr := &sftpBody{b}

	version, err := vr.u32()
	if err != nil || version != 3 {
		fatalf("bad sftp version %d", version)
	}

	if put {
		if err := s3RunSFTPPut(c, local, remote); err != nil {
			fmt.Fprintf(os.Stderr, "harness: sftp put: %v\n", err)
			os.Exit(1)
		}

		return
	}

	if err := s3RunSFTPGet(c, local, remote); err != nil {
		fmt.Fprintf(os.Stderr, "harness: sftp get: %v\n", err)
		os.Exit(1)
	}
}

// === agent forwarding, the -h3-agent-* modes ===
//
// The reference flow (cmd/ssh3-server.go): a 94 data frame carrying
// exactly "forward-agent" on a session channel still in LARVAL creates
// the agent unix socket (a temp dir with agent.<pid>, like
// unix_util.NewUnixSocketPath); every connection accepted on it opens
// one server-initiated "agent-connection" channel (maxPacketSize
// 30000) and the bytes pump both ways as 94 frames.  The exec requests
// run with SSH_AUTH_SOCK pointing at the socket.  The client accepts
// those channels, confirms them with 91 and bridges them to its local
// SSH_AUTH_SOCK.

const (
	s3AgentTrigger     = "forward-agent"
	s3AgentChannelType = "agent-connection"
	s3AgentMaxPacket   = 30000
	s3AgentPumpChunk   = 16384 // far below the 30000 maxPacketSize
)

// runH3AgentServer serves the agent scenarios: the session channel
// machinery of -h3-session-server plus the LARVAL trigger
func runH3AgentServer(addr, certFile, keyFile string) {
	s3RunRawH3Server(addr, certFile, keyFile, "h3-agent-server",
		func(server *http3.Server, conn *quic.Conn) {
			s3ServeChannels(server, conn, func(str *quic.Stream, convID uint64) {
				s3HandleAgentSessionChannel(str, conn, convID)
			})
		})
}

// s3HandleAgentSessionChannel runs one accepted session channel of the
// agent server: the exec/signals flow of the session server plus the
// LARVAL trigger — a 94 data frame "forward-agent" before the first
// request creates the agent unix socket, later 94 payloads feed the
// process stdin
func s3HandleAgentSessionChannel(str *quic.Stream, conn *quic.Conn, convID uint64) {
	br := bufio.NewReader(str)

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
		wmu       sync.Mutex // serializes every write to the channel stream
		cmd       *exec.Cmd
		stdin     io.WriteCloser
		larval    = true
		agentPath string
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
		case 94: // SSH_MSG_CHANNEL_DATA
			data, err := s3ReadSSHString(br)
			if err != nil {
				return
			}

			if larval {
				// the LARVAL state of the reference: only the
				// forward-agent marker is legal here
				if string(data) != s3AgentTrigger {
					str.CancelRead(42)
					str.CancelWrite(42)
					return
				}

				agentPath = s3StartAgentListener(conn, convID)
				larval = false

				continue
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

				var env []string

				if agentPath != "" {
					env = append(env, "SSH_AUTH_SOCK="+agentPath)
				}

				c, cin, ok := s3SpawnExec(str, &wmu, string(command), env)
				if !ok {
					continue
				}

				wmu.Lock()
				cmd = c
				stdin = cin
				wmu.Unlock()

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

// s3StartAgentListener creates the agent unix socket (a temp dir with
// agent.<pid> like the reference unix_util.NewUnixSocketPath), listens
// and forwards every accepted connection through one server-initiated
// "agent-connection" channel; it returns the socket path for the
// SSH_AUTH_SOCK of the exec env
func s3StartAgentListener(conn *quic.Conn, convID uint64) string {
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "harness: agent temp dir: %v\n", err)
		return ""
	}

	sockPath := filepath.Join(dir, fmt.Sprintf("agent.%d", os.Getpid()))

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "harness: agent listen: %v\n", err)
		return ""
	}

	fmt.Printf("AGENT-GO-SOCKET-READY sock=%s\n", sockPath)

	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				_ = listener.Close()
				return
			}

			go s3HandleAgentSocketConn(c, conn, convID)
		}
	}()

	return sockPath
}

// s3HandleAgentSocketConn pumps one accepted agent socket through one
// server-initiated "agent-connection" channel (the reference
// handleAuthAgentSocketConn): the socket reads ride as 94 frames, the
// channel payloads go back into the socket; the client's 91
// confirmation on the server-initiated channel is skipped
func s3HandleAgentSocketConn(sock net.Conn, conn *quic.Conn, convID uint64) {
	str, err := conn.OpenStream()
	if err != nil {
		sock.Close()
		return
	}

	header := s3AppendVarint(nil, s3SSHFrameType)
	header = s3AppendVarint(header, convID)
	header = s3AppendSSHString(header, []byte(s3AgentChannelType))
	header = s3AppendVarint(header, s3AgentMaxPacket)

	if _, err := str.Write(header); err != nil {
		str.CancelRead(0)
		str.CancelWrite(0)
		sock.Close()
		return
	}

	go s3PumpSocketToChannel(str, sock)

	br := bufio.NewReader(str)

	s3PipeChannelToSocket(str, br, sock)
}

// s3PumpSocketToChannel forwards one local socket to the channel as 94
// frames (one per read chunk); the socket EOF closes the stream with
// the FIN, a write error tears the socket down
func s3PumpSocketToChannel(str *quic.Stream, sock io.ReadWriteCloser) {
	buf := make([]byte, s3AgentPumpChunk)

	for {
		n, err := sock.Read(buf)

		if n > 0 {
			frame := s3AppendVarint(nil, 94)
			frame = s3AppendSSHString(frame, buf[:n])

			if _, werr := str.Write(frame); werr != nil {
				sock.Close()
				return
			}
		}

		if err != nil {
			_ = str.Close() // the socket EOF: the stream FIN
			return
		}
	}
}

// s3PipeChannelToSocket drives the inbound side of an agent-connection
// channel: the 91 confirmations of the peer are skipped, the 94/95
// payloads ride the local socket (both data kinds, like the reference
// handleAuthAgentSocketConn); the stream EOF or a foreign message
// closes both ends
func s3PipeChannelToSocket(str *quic.Stream, br *bufio.Reader, sock net.Conn) {
	for {
		typ, err := s3ReadVarint(br)
		if err != nil {
			sock.Close()
			return
		}

		switch typ {
		case 91:
			if _, err := s3ReadVarint(br); err != nil { // maxPacketSize
				sock.Close()
				return
			}

		case 94, 95:
			if typ == 95 {
				if _, err := s3ReadVarint(br); err != nil { // data type
					sock.Close()
					return
				}
			}

			data, err := s3ReadSSHString(br)
			if err != nil {
				sock.Close()
				return
			}

			if _, err := sock.Write(data); err != nil {
				str.CancelRead(0)
				str.CancelWrite(0)
				return
			}

		default:
			str.CancelRead(0)
			str.CancelWrite(0)
			sock.Close()
			return
		}
	}
}

// runH3AgentClient runs the session exec scenario of
// -h3-session-client plus the agent forwarding: the 94 data frame
// "forward-agent" rides before the exec request (the LARVAL trigger),
// the server-initiated "agent-connection" channels are accepted in the
// background and bridged to the local SSH_AUTH_SOCK
func runH3AgentClient(target string, timeout time.Duration, command string) {
	if target == "" {
		fatalf("h3-agent-client mode needs -a host:port")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, str := s3DialAndConnect(target, ctx, timeout)
	defer conn.CloseWithError(0, "")

	convID := uint64(str.StreamID())

	// the server-initiated agent channels arrive as peer bidis
	go func() {
		for {
			s, err := conn.AcceptStream(context.Background())
			if err != nil {
				return
			}

			go s3HandleAgentConnectionChannel(s, convID, timeout)
		}
	}()

	// the session channel burst: the header, the forward-agent marker
	// (the LARVAL trigger) and the exec
	ch, err := conn.OpenStream()
	if err != nil {
		fatalf("open channel stream: %v", err)
	}

	if err := ch.SetDeadline(time.Now().Add(timeout)); err != nil {
		fatalf("set channel deadline: %v", err)
	}

	header := s3AppendVarint(nil, s3SSHFrameType)
	header = s3AppendVarint(header, convID)
	header = s3AppendSSHString(header, []byte("session"))
	header = s3AppendVarint(header, s3ChannelMaxPacket)

	marker := s3AppendVarint(nil, 94)
	marker = s3AppendSSHString(marker, []byte(s3AgentTrigger))

	execReq := s3AppendVarint(nil, 98)
	execReq = s3AppendSSHString(execReq, []byte("exec"))
	execReq = append(execReq, 1) // want_reply = 1
	execReq = s3AppendSSHString(execReq, []byte(command))

	burst := append(header, marker...)
	burst = append(burst, execReq...)

	if _, err := ch.Write(burst); err != nil {
		fatalf("write channel: %v", err)
	}

	// the exec carries no stdin: the fin goes out at once (the
	// receive side stays open), like -h3-session-client
	if err := ch.Close(); err != nil {
		fatalf("close channel: %v", err)
	}

	code, out := s3SessionExecRead(ch, false)

	// the -cmd runs (the agent_probe of the fork) answer with their
	// own marker, the plain exec wants the printf one

	if code == 0 && (bytes.Contains(out, []byte("s3-exec-ok")) ||
		bytes.Contains(out, []byte("SSH3_AGENT_PROBE_OK"))) {
		fmt.Println("INTEROP-GO-EXEC-OK exit=0")
		return
	}

	fmt.Printf("INTEROP-GO-EXEC-FAIL exit=%d\n", code)
	os.Exit(1)
}

// s3HandleAgentConnectionChannel bridges one server-initiated
// "agent-connection" channel to the local SSH_AUTH_SOCK: the header is
// answered with the 91 confirmation (the shape of the server) and the
// bytes pump both ways until either end closes
func s3HandleAgentConnectionChannel(str *quic.Stream, convID uint64, timeout time.Duration) {
	br := bufio.NewReader(str)

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

	if ftype != s3SSHFrameType || convid != convID || string(ctype) != s3AgentChannelType {
		str.CancelRead(0)
		str.CancelWrite(0)
		return
	}

	// the deadline guards the handshake only: an established bridge
	// may idle as long as the peers keep it
	if err := str.SetDeadline(time.Now().Add(timeout)); err != nil {
		str.CancelRead(0)
		str.CancelWrite(0)
		return
	}

	if _, err := str.Write(s3AppendVarint(s3AppendVarint(nil, 91), s3ChannelMaxPacket)); err != nil {
		return
	}

	sockPath := os.Getenv("SSH_AUTH_SOCK")
	if sockPath == "" {
		fmt.Fprintf(os.Stderr, "harness: agent bridge: SSH_AUTH_SOCK is unset\n")
		str.CancelRead(0)
		str.CancelWrite(0)
		return
	}

	sock, err := net.Dial("unix", sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "harness: agent dial %s: %v\n", sockPath, err)
		str.CancelRead(0)
		str.CancelWrite(0)
		return
	}

	if err := str.SetDeadline(time.Time{}); err != nil {
		str.CancelRead(0)
		str.CancelWrite(0)
		sock.Close()
		return
	}

	fmt.Println("AGENT-GO-BRIDGE")

	go s3PumpSocketToChannel(str, sock)

	s3PipeChannelToSocket(str, br, sock)
}

// MARKER-TEST
