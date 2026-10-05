//go:build !unix

package main

// SPDX-License-Identifier: BSD-2-Clause

// The -h3-session-client -pty mode needs a unix pty pair; the harness
// pty scenario runs under WSL/Linux only.

import "time"

func runH3SessionPtyClient(target string, timeout time.Duration, command string) {
	fatalf("the -pty mode is unix-only")
}
