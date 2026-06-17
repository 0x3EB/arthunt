package scan

import (
	"regexp"
	"strings"
)

// Well-known placeholder / documentation / test values that should never be
// reported as live secrets.
var placeholderExact = map[string]bool{
	"AKIAIOSFODNN7EXAMPLE":                     true,
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": true,
	"EXAMPLE":                          true,
	"example":                          true,
	"changeme":                         true,
	"password":                         true,
	"changeit":                         true,
	"secret":                           true,
	"redacted":                         true,
	"REDACTED":                         true,
	"xxxxxxxx":                         true,
	"your_api_key":                     true,
	"your-api-key":                     true,
	"yourapikey":                       true,
	"none":                             true,
	"null":                             true,
	"true":                             true,
	"false":                            true,
	"00000000000000000000000000000000": true,
}

// placeholderSubstr: "wordy" markers unlikely to appear inside a real secret,
// so a substring match is safe.
var placeholderSubstr = []string{
	"example", "xxxxx", "placeholder", "your_", "your-", "yourtoken",
	"changeme", "change_me", "dummy", "test_test", "sample", "redacted",
	"insert_", "<your", "notreal", "todo", "lorem", "foobar",
	"secretsecret", "asdfasdf", "qwerty",
}

// sequenceSubstr: low-entropy sequences that CAN legitimately occur inside a
// genuine high-entropy secret, so they only count as placeholders when the
// candidate is short (typical of doc/test fixtures), not for long real keys.
var sequenceSubstr = []string{
	"01234567", "abcdefgh", "deadbeef", "0xdeadbeef", "aaaaaa", "bbbbbb",
	"123456789", "fake",
}

// Template / interpolation OPENING markers => the "secret" is a variable
// reference, not a literal. Only opening markers are listed; a lone "}" would
// wrongly suppress real secrets that happen to contain a closing brace.
var templateMarkers = []string{
	"${", "{{", "%(", "#{", "<%", "$(",
}

var (
	reMavenEncrypt = regexp.MustCompile(`^\{[A-Za-z0-9+/=]{8,}\}$`) // Maven encrypted {...}
	reHexLike      = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// isAllSameChar reports whether s is one character repeated (RE2 has no
// backreferences, so this replaces a `^(.)\1{5,}$` pattern).
func isAllSameChar(s string) bool {
	if len(s) < 6 {
		return false
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

// isFalsePositive applies cheap, conservative heuristics to drop obvious noise.
func isFalsePositive(secret string, r *Rule) bool {
	s := strings.TrimSpace(secret)
	if s == "" {
		return true
	}
	lower := strings.ToLower(s)

	if placeholderExact[s] {
		return true
	}
	for _, sub := range placeholderSubstr {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	// Low-entropy sequences only disqualify SHORT candidates (doc/test values);
	// a long real secret merely containing such a run is not suppressed.
	if len(s) <= 24 {
		for _, sub := range sequenceSubstr {
			if strings.Contains(lower, sub) {
				return true
			}
		}
	}
	// Maven {encrypted} server passwords are not plaintext secrets.
	if reMavenEncrypt.MatchString(s) {
		return true
	}
	// Single repeated character (e.g. "aaaaaaaa", "********").
	if isAllSameChar(s) {
		return true
	}
	// Pure punctuation / masking characters.
	if strings.Trim(s, "*•#.-_= ") == "" {
		return true
	}
	// Obvious template variable rather than a value.
	for _, m := range templateMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	// For generic/entropy rules, demand a minimum of character diversity so we
	// don't flag sequential or low-variety strings the entropy gate let slip.
	if r != nil && (r.Category == "generic" || strings.HasPrefix(r.ID, "generic")) {
		if uniqueRunes(s) < 5 {
			return true
		}
		// Pure-hex values at common checksum/commit/UUID lengths (md5=32,
		// sha1/commit=40) are almost never secrets — suppress for generic rules.
		if reHexLike.MatchString(s) {
			n := len(s)
			if n <= 16 || n == 32 || n == 40 || n == 64 {
				return true // md5/sha1/sha256/commit/UUID-shaped — not a secret
			}
		}
	}
	return false
}

func uniqueRunes(s string) int {
	seen := make(map[rune]struct{}, len(s))
	for _, r := range s {
		seen[r] = struct{}{}
	}
	return len(seen)
}
