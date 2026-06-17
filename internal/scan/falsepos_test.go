package scan

import (
	"strings"
	"testing"
)

// benignCorpus is realistic non-secret content a scan will routinely encounter
// in build artifacts. None of it should produce a finding.
var benignCorpus = map[string]string{
	"checksums.txt": strings.Join([]string{
		"md5    5d41402abc4b2a76b9719d911017c592  app.jar",
		"sha1   aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d  app.jar",
		"sha256 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae  app.jar",
	}, "\n"),
	"CHANGELOG.md": strings.Join([]string{
		"## v1.2.3-beta.4+build.567 (2026-01-01)",
		"- fixed in commit e83c5163316f89bfbde7d9ab23ca2e25604af290",
		"- see also a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
	}, "\n"),
	"ids.json": `{"uuid":"550e8400-e29b-41d4-a716-446655440000","trace":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}`,
	"package-lock.snippet": strings.Join([]string{
		`"lodash": {`,
		`  "version": "4.17.21",`,
		`  "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",`,
		`  "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="`,
		`}`,
	}, "\n"),
	"data-uri.html": `<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==">`,
	"config.yaml": strings.Join([]string{
		"password: changeme",
		"api_key: ${API_KEY}",
		"token: your-token-here",
		"client_secret: \"\"",
		"db_url: postgres://user:${DB_PASSWORD}@localhost:5432/app",
		"aws_region: us-east-1",
	}, "\n"),
	"source.go": strings.Join([]string{
		`// the secret sauce of this algorithm is documented here`,
		`var defaultKey = os.Getenv("APP_KEY")`,
		`const tokenHeader = "Authorization"`,
		`logger.Info("loaded api key from vault")`,
		`hash := sha256.Sum256(data) // returns 32 bytes`,
	}, "\n"),
	"prose.txt": strings.Join([]string{
		"Refer to clause s.12 of the agreement and section 4.2 thereof.",
		"The class diagram shows Maps.Entry and List.of usage patterns.",
		"Visit https://example.com/docs for the full reference.",
	}, "\n"),
	"base64-blobs.txt": strings.Join([]string{
		// arbitrary base64 payloads (not credentials) that begin with letters
		// some detectors anchor on (e.g. 'YC', 'eyJ' non-JWT).",
		"payload1=YCdGhpcyBpcyBhIHJlYWxseSBsb25nIGJhc2U2NCBibG9iIHN0cmluZw",
		"payload2=AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAtest1234567890abcdef",
	}, "\n"),
}

func TestNoFalsePositivesOnBenignCorpus(t *testing.T) {
	rules, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	var total int
	for name, content := range benignCorpus {
		li := newLineIndex([]byte(content))
		fs := matchRules(rules, []byte(content), li, "")
		for _, f := range fs {
			if isFalsePositive(f.Secret, ruleByID(rules, f.RuleID)) {
				continue // would be dropped by the engine's allowlist pass
			}
			total++
			t.Errorf("FALSE POSITIVE in %s: rule=%s line=%d match=%q secret=%q",
				name, f.RuleID, f.Line, f.Match, f.Secret)
		}
	}
	if total == 0 {
		t.Logf("clean: 0 false positives across %d benign files, %d rules", len(benignCorpus), len(rules))
	}
}

func ruleByID(rules []Rule, id string) *Rule {
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i]
		}
	}
	return nil
}
