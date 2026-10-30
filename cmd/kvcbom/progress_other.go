//go:build !windows

package main

import "os"

// enableVirtualTerminal is a no-op off Windows: Unix terminals handle ANSI
// escape sequences natively.
func enableVirtualTerminal(_ *os.File) {}
