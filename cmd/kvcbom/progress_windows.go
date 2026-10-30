//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// enableVirtualTerminalProcessing on Windows 10+ turns on ANSI escape handling
// for the given console so the green check renders instead of raw escape codes.
// It is best-effort: any failure (e.g. output is not a real console) is ignored,
// and uses only the standard library to keep the build dependency-free.
func enableVirtualTerminal(f *os.File) {
	const enableVTProcessing = 0x0004
	handle := syscall.Handle(f.Fd())
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")

	var mode uint32
	if r, _, _ := getConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode))); r == 0 {
		return
	}
	setConsoleMode.Call(uintptr(handle), uintptr(mode|enableVTProcessing))
}
