//go:build windows

package scan

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode             = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode             = kernel32.NewProc("SetConsoleMode")
	procGetConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
)

const enableVirtualTerminalProcessing = 0x0004

type coord struct{ X, Y int16 }
type smallRect struct{ Left, Top, Right, Bottom int16 }
type consoleScreenBufferInfo struct {
	Size              coord
	CursorPosition    coord
	Attributes        uint16
	Window            smallRect
	MaximumWindowSize coord
}

// initTerminal enables ANSI (Virtual Terminal Processing) on the Windows console
// — required for cmd.exe to interpret escape codes — and returns whether f is a
// console plus its width. On failure it reports tty=false so the caller falls
// back to plain line output.
func initTerminal(f *os.File) (tty bool, width int) {
	h := syscall.Handle(f.Fd())
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode))); r == 0 {
		return false, 0 // not a console (redirected to a file/pipe)
	}
	// Best-effort: enable ANSI. If it can't be set, ANSI may still work on
	// Windows Terminal; we proceed and let the caller render.
	procSetConsoleMode.Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))

	var info consoleScreenBufferInfo
	if r, _, _ := procGetConsoleScreenBufferInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&info))); r != 0 {
		if w := int(info.Window.Right-info.Window.Left) + 1; w > 0 {
			width = w
		}
	}
	return true, width
}
