//go:build unix

package main

// SPDX-License-Identifier: BSD-2-Clause

// The -h3-session-client -pty mode: the fork's forced-pty session over
// the C server.  A programmatic pty pair replaces the live terminal
// (creack/pty), the pty-req carries its 80x24 geometry and the resizes
// of the pair ride the SIGWINCH relay as window-change requests, the
// fork's cmd/forced_pty.go + cmd/window_change_unix.go shape.
//
// The verdict: the exec probe (the -cmd) prints the geometry twice
// around its own sleep, the second line must show the resized 40x100
// the server applied through the window-change.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/creack/pty"
)

func runH3SessionPtyClient(target string, timeout time.Duration, command string) {
	if target == "" {
		fatalf("h3-session-client mode needs -a host:port")
	}

	if command == "" {
		fatalf("h3-session-client -pty mode needs -cmd with the geometry probe")
	}

	ptyF, ttyF, err := pty.Open()
	if err != nil {
		fatalf("open pty: %v", err)
	}
	defer ptyF.Close()
	defer ttyF.Close()

	if err := pty.Setsize(ptyF, &pty.Winsize{Rows: 24, Cols: 80}); err != nil {
		fatalf("set pty size: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, str := s3DialAndConnect(target, ctx, timeout, false)
	defer conn.CloseWithError(0, "")

	ch, err := conn.OpenStream()
	if err != nil {
		fatalf("open channel stream: %v", err)
	}

	if err := ch.SetDeadline(time.Now().Add(timeout)); err != nil {
		fatalf("set channel deadline: %v", err)
	}

	// the channel: a fresh bidi stream, the header quotes the control
	// stream id (ChannelID == StreamID, docs/P4-WIRE.md 2)
	header := s3AppendVarint(nil, s3SSHFrameType)
	header = s3AppendVarint(header, uint64(str.StreamID()))
	header = s3AppendSSHString(header, []byte("session"))
	header = s3AppendVarint(header, s3ChannelMaxPacket)

	ptyReq := s3AppendVarint(nil, 98)
	ptyReq = s3AppendSSHString(ptyReq, []byte("pty-req"))
	ptyReq = append(ptyReq, 1) // want_reply = 1
	ptyReq = s3AppendSSHString(ptyReq, []byte("xterm"))
	ptyReq = s3AppendVarint(ptyReq, 80)     // cols
	ptyReq = s3AppendVarint(ptyReq, 24)     // rows
	ptyReq = s3AppendVarint(ptyReq, 0)      // pixel width
	ptyReq = s3AppendVarint(ptyReq, 0)      // pixel height
	ptyReq = s3AppendSSHString(ptyReq, nil) // modes

	execReq := s3AppendVarint(nil, 98)
	execReq = s3AppendSSHString(execReq, []byte("exec"))
	execReq = append(execReq, 1) // want_reply = 1
	execReq = s3AppendSSHString(execReq, []byte(command))

	if _, err := ch.Write(append(header, append(ptyReq, execReq...)...)); err != nil {
		fatalf("write channel: %v", err)
	}

	// the SIGWINCH relay: every resize of the local pair rides as a
	// window-change request (want_reply = 0), the geometry is read off
	// the pair like the fork relay does off the terminal
	sigwinch := make(chan os.Signal, 1)
	signal.Notify(sigwinch, syscall.SIGWINCH)
	defer signal.Stop(sigwinch)

	go func() {
		for range sigwinch {
			ws, err := pty.GetsizeFull(ptyF)
			if err != nil {
				continue
			}

			wc := s3AppendVarint(nil, 98)
			wc = s3AppendSSHString(wc, []byte("window-change"))
			wc = append(wc, 0) // want_reply = 0
			wc = s3AppendVarint(wc, uint64(ws.Cols))
			wc = s3AppendVarint(wc, uint64(ws.Rows))
			wc = s3AppendVarint(wc, 0)
			wc = s3AppendVarint(wc, 0)

			if _, err := ch.Write(wc); err != nil {
				return
			}
		}
	}()

	// the probe prints the geometry twice around the exec's sleep:
	// after the first line is out, the pair resizes and SIGWINCH
	// fires; the stream stays writable for the window-change, no fin
	// here, unlike the plain exec mode
	onConfirmed := func() {
		time.Sleep(500 * time.Millisecond)

		if err := pty.Setsize(ptyF, &pty.Winsize{Rows: 40, Cols: 100}); err != nil {
			fatalf("resize pty: %v", err)
		}

		if err := syscall.Kill(syscall.Getpid(), syscall.SIGWINCH); err != nil {
			fatalf("raise sigwinch: %v", err)
		}
	}

	code, out := s3SessionExecRead(ch, onConfirmed)

	first := bytes.Index(out, []byte("24 80"))
	resized := bytes.Index(out, []byte("40 100"))

	if code == 0 && first >= 0 && resized > first {
		fmt.Println("INTEROP-GO-PTY-OK resize=40x100")
		return
	}

	if len(out) > 256 {
		out = out[:256]
	}

	fmt.Printf("INTEROP-GO-PTY-FAIL exit=%d out=%q\n", code, out)
	os.Exit(1)
}
