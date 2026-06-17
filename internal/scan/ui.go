package scan

import (
	"os"
	"strings"
	"sync"
)

// dashboard is a minimal sticky-header live display: a fixed header block is
// rewritten in place at the top of the screen on every update, and the most
// recent finding lines stream in a window just below it. It repaints from cursor
// home each time (no scroll regions), which is the most broadly compatible ANSI
// technique once Virtual Terminal Processing is on. All findings still go to the
// report; this is only the live view, capped to the last maxLines findings.
type dashboard struct {
	mu       sync.Mutex
	out      *os.File
	width    int
	maxLines int
	header   []string
	tail     []string
}

const (
	ansiHome   = "\033[H"
	ansiClrEOL = "\033[K"
	ansiClrEOS = "\033[J"
	ansiClear  = "\033[2J\033[H"
)

func newDashboard(out *os.File, width int) *dashboard {
	if width <= 0 {
		width = 120
	}
	d := &dashboard{out: out, width: width, maxLines: 15}
	out.WriteString(ansiClear)
	return d
}

// setHeader replaces the fixed header block and repaints.
func (d *dashboard) setHeader(lines []string) {
	d.mu.Lock()
	d.header = lines
	d.render()
	d.mu.Unlock()
}

// addLine appends a finding line to the streaming window and repaints.
func (d *dashboard) addLine(line string) {
	d.mu.Lock()
	d.tail = append(d.tail, line)
	if len(d.tail) > d.maxLines {
		d.tail = d.tail[len(d.tail)-d.maxLines:]
	}
	d.render()
	d.mu.Unlock()
}

// render repaints header + tail from the top of the screen. Caller holds d.mu.
func (d *dashboard) render() {
	var b strings.Builder
	b.WriteString(ansiHome)
	for _, h := range d.header {
		b.WriteString(clip(h, d.width))
		b.WriteString(ansiClrEOL)
		b.WriteByte('\n')
	}
	for _, l := range d.tail {
		b.WriteString(clip(l, d.width))
		b.WriteString(ansiClrEOL)
		b.WriteByte('\n')
	}
	b.WriteString(ansiClrEOS) // wipe anything left below from a taller prior frame
	d.out.WriteString(b.String())
}

// close paints the final frame and moves the cursor below it so the summary
// prints cleanly underneath.
func (d *dashboard) close() {
	d.mu.Lock()
	d.render()
	d.out.WriteString("\n")
	d.mu.Unlock()
}

// clip truncates to w runes so a long line never wraps and breaks the layout.
// Lines are kept plain (no colour codes) so the rune count equals the on-screen
// width.
func clip(s string, w int) string {
	if w <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) > w {
		return string(r[:w])
	}
	return s
}
