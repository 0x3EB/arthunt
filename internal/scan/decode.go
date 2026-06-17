package scan

import (
	"encoding/base64"
	"regexp"
)

// base64Regexes match long base64 runs. Standard (+/) and URL-safe (-_)
// alphabets are matched by separate patterns so a run is captured cleanly in one
// alphabet instead of as a mixed, undecodable blob.
var (
	reBase64Std = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)
	reBase64URL = regexp.MustCompile(`[A-Za-z0-9_-]{24,}={0,2}`)

	base64Regexes = []*regexp.Regexp{reBase64Std, reBase64URL}
)

// decodeBase64 attempts several base64 variants, returning nil on failure.
func decodeBase64(b []byte) []byte {
	s := string(b)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if dec, err := enc.DecodeString(s); err == nil && len(dec) > 0 {
			return dec
		}
	}
	return nil
}
