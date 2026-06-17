//go:build !windows

package scan

import "os"

// initTerminal reports whether f is an interactive terminal and its width
// (0 = unknown → caller uses a default). On non-Windows, ANSI works without any
// console mode change, so we only need char-device detection.
func initTerminal(f *os.File) (tty bool, width int) {
	fi, err := f.Stat()
	if err != nil {
		return false, 0
	}
	return fi.Mode()&os.ModeCharDevice != 0, 0
}
