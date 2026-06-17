package scan

import (
	"strings"
	"testing"
	"time"
)

func TestClip(t *testing.T) {
	if got := clip("hello world", 5); got != "hello" {
		t.Errorf("clip=%q want hello", got)
	}
	if got := clip("hi", 5); got != "hi" {
		t.Errorf("clip=%q want hi", got)
	}
	if got := clip("héllo", 3); got != "hél" { // rune-safe (é is one rune)
		t.Errorf("clip=%q want hél", got)
	}
}

func TestFmtDur(t *testing.T) {
	cases := map[time.Duration]string{
		5 * time.Second:  "5s",
		90 * time.Second: "1m30s",
		(2*time.Hour + 3*time.Minute + 4*time.Second): "2h03m04s",
	}
	for d, want := range cases {
		if got := fmtDur(d); got != want {
			t.Errorf("fmtDur(%v)=%q want %q", d, got, want)
		}
	}
}

func TestMarkRepoDone(t *testing.T) {
	e := NewEngine(nil, nil, Config{})
	e.repoRemaining = map[string]int{"a": 2, "b": 1}
	e.reposTotal = 2

	e.markRepoDone("a")
	if e.reposDone.Load() != 0 {
		t.Fatalf("repo a not finished yet, done=%d", e.reposDone.Load())
	}
	e.markRepoDone("a")
	e.markRepoDone("b")
	if e.reposDone.Load() != 2 {
		t.Fatalf("expected 2 repos done, got %d", e.reposDone.Load())
	}
	// Extra calls for an already-finished repo must not double-count.
	e.markRepoDone("a")
	if e.reposDone.Load() != 2 {
		t.Fatalf("double counted: %d", e.reposDone.Load())
	}
}

func TestHeaderLines(t *testing.T) {
	e := NewEngine(nil, nil, Config{})
	e.reposTotal = 3
	e.reposDone.Store(1)
	e.stat.filesProcessed.Store(50)
	e.stat.sevCrit.Store(2)
	lines := e.headerLines(200, time.Now().Add(-time.Minute))
	if len(lines) != 4 {
		t.Fatalf("expected 4 header lines, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "repos 1/3") || !strings.Contains(lines[0], "50/200") {
		t.Errorf("header line0 unexpected: %q", lines[0])
	}
	if !strings.Contains(lines[1], "crit 2") {
		t.Errorf("header line1 unexpected: %q", lines[1])
	}
}
