package scan

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"math"
)

// shannonEntropy returns bits-of-entropy per character of s.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// toLowerASCII lowercases ASCII letters in-place on a copy, for keyword
// pre-filtering without allocating per-keyword.
func toLowerASCII(b []byte) []byte {
	out := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// keywordHit reports whether any keyword appears in the (already lowercased)
// content. An empty keyword list means "always consider this rule".
func keywordHit(lowerContent []byte, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	for _, k := range keywords {
		if k == "" {
			return true
		}
		if bytes.Contains(lowerContent, []byte(k)) {
			return true
		}
	}
	return false
}

// lineIndex maps byte offsets to 1-based line/column.
type lineIndex struct {
	starts []int // byte offset of the start of each line
}

func newLineIndex(content []byte) *lineIndex {
	starts := []int{0}
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &lineIndex{starts: starts}
}

func (li *lineIndex) at(offset int) (line, col int) {
	// binary search for the greatest start <= offset
	lo, hi := 0, len(li.starts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if li.starts[mid] <= offset {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1, offset - li.starts[lo] + 1
}

// redactValue masks a secret for the default (no --show-secrets) report.
// Short OR low-entropy values (human passwords, PINs) are fully masked so no
// head/tail is leaked; only long, high-entropy tokens keep a 4-char
// non-sensitive prefix (e.g. "AKIA", "ghp_") to aid triage. There is never a
// trailing reveal.
func redactValue(secret string, entropy float64) string {
	r := []rune(collapse(secret))
	n := len(r)
	if n == 0 {
		return "****"
	}
	if n < 16 || entropy < 3.5 {
		return "****"
	}
	return string(r[:4]) + "…[redacted " + itoa(n) + "]"
}

// collapse trims and squeezes whitespace so a multi-line match stays one line.
func collapse(s string) string {
	var b []byte
	prevSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' || c == '\r' || c == '\t' || c == ' ' {
			if !prevSpace {
				b = append(b, ' ')
				prevSpace = true
			}
			continue
		}
		b = append(b, c)
		prevSpace = false
	}
	out := string(bytes.TrimSpace(b))
	if r := []rune(out); len(r) > 200 {
		out = string(r[:200]) + "…" // rune-safe truncation (no split multibyte)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// fingerprint builds a stable dedup/identity key for a finding.
func fingerprint(ruleID, repo, path string, secret string) string {
	h := sha1.New()
	h.Write([]byte(ruleID))
	h.Write([]byte{0})
	h.Write([]byte(repo))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write([]byte(secret))
	return hex.EncodeToString(h.Sum(nil))[:16]
}
