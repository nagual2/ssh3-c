// SPDX-License-Identifier: BSD-2-Clause

// The quic-go interop harness for ssh3-c (D3 acceptance).
//
// One binary, two modes:
//
//	harness -server -addr 127.0.0.1:0 -cert cert.pem -key key.pem
//	harness -client -addr 127.0.0.1:4433 -count 8 -size 512
//
// The server accepts QUIC connections and echoes every received
// DATAGRAM back.  The client dials, sends count datagrams of the
// requested size and verifies the echoes byte for byte.
//
// Machine-readable lines on stdout (the runner greps them):
//
//	INTEROP-LISTEN port=N
//	INTEROP-HANDSHAKE-OK
//	INTEROP-DATAGRAM-OK sent=N recv=N
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
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
	size := flag.Int("size", 512, "datagram payload size (client)")
	timeout := flag.Duration("timeout", 20*time.Second, "overall deadline (client)")
	keylog := flag.String("keylog", "", "NSS keylog file for the client TLS secrets")
	flag.Parse()

	if *size > 1100 {
		// the datagram must fit the 1200 byte max_datagram_frame_size
		// advertised by the ssh3-c runners with a frame header on top
		*size = 1100
	}

	if *server && *client {
		fatalf("-server and -client are mutually exclusive")
	}

	if *server {
		runServer(*addr, *certFile, *keyFile, *alpn, *keylog)
		return
	}

	runClient(*addr, *alpn, *count, *size, *timeout, *keylog)
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

		go echoDatagrams(conn)
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

func runClient(addr, alpn string, count, size int, timeout time.Duration, keylog string) {
	if count < 1 {
		fatalf("-count must be positive")
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

	for received < count {
		data, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			fatalf("receive datagram after %d/%d: %v", received, count, err)
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
