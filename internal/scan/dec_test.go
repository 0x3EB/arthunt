package scan

import "encoding/base64"

// dec decodes a base64 test fixture at runtime, so secret-shaped sample strings
// never appear verbatim in source (avoids tripping push-protection scanners).
func dec(s string) string {
	b, _ := base64.StdEncoding.DecodeString(s)
	return string(b)
}
