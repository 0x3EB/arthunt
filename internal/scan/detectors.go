package scan

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

//go:embed rules.json
var embeddedRules []byte

// rawRule is the on-disk/embedded representation of a detector.
type rawRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Regex       string   `json:"regex"`
	Keywords    []string `json:"keywords"`
	EntropyMin  float64  `json:"entropy_min"`
	Description string   `json:"description"`
}

type ruleFile struct {
	Version string    `json:"version"`
	Rules   []rawRule `json:"rules"`
}

// Rule is a compiled detector.
type Rule struct {
	ID         string
	Name       string
	Severity   string
	Category   string
	Keywords   []string // lowercased substrings for fast pre-filtering
	EntropyMin float64
	re         *regexp.Regexp
}

// Finding is a single secret detection.
type Finding struct {
	RuleID      string  `json:"rule_id"`
	RuleName    string  `json:"rule_name"`
	Severity    string  `json:"severity"`
	Category    string  `json:"category"`
	Repo        string  `json:"repo"`
	Path        string  `json:"path"`
	FileURL     string  `json:"file_url"`
	Line        int     `json:"line"`
	Column      int     `json:"column"`
	Match       string  `json:"match"`            // redacted unless ShowSecrets
	Secret      string  `json:"secret,omitempty"` // populated only when ShowSecrets
	Entropy     float64 `json:"entropy"`
	Sha256      string  `json:"sha256,omitempty"`
	Size        int64   `json:"size"`
	ViaDecoder  string  `json:"via_decoder,omitempty"` // e.g. "base64"
	Fingerprint string  `json:"fingerprint"`           // stable dedup key
}

// RulesetVersion returns the version field from the embedded ruleset.
func RulesetVersion() string {
	var rf ruleFile
	if err := json.Unmarshal(embeddedRules, &rf); err != nil {
		return "unknown"
	}
	if rf.Version == "" {
		return "unknown"
	}
	return rf.Version
}

var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

// SeverityRank returns a comparable weight for a severity label.
func SeverityRank(s string) int { return severityRank[strings.ToLower(s)] }

// LoadRules compiles the embedded ruleset, optionally extended/overridden by an
// external JSON file (same schema). Invalid regexes are skipped with a warning
// so one bad rule can never break a scan.
func LoadRules(extraPath string) ([]Rule, error) {
	var rf ruleFile
	if err := json.Unmarshal(embeddedRules, &rf); err != nil {
		return nil, fmt.Errorf("parse embedded rules: %w", err)
	}
	raws := rf.Rules

	if extraPath != "" {
		data, err := os.ReadFile(extraPath)
		if err != nil {
			return nil, fmt.Errorf("read --rules %s: %w", extraPath, err)
		}
		var extra ruleFile
		if err := json.Unmarshal(data, &extra); err != nil {
			return nil, fmt.Errorf("parse --rules %s: %w", extraPath, err)
		}
		raws = append(raws, extra.Rules...)
	}

	seen := make(map[string]bool)
	var rules []Rule
	var skipped int
	for _, r := range raws {
		if r.ID == "" || r.Regex == "" {
			continue
		}
		if seen[r.ID] {
			continue // later duplicates ignored; first wins
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] rule %q skipped (invalid RE2 regex): %v\n", r.ID, err)
			skipped++
			continue
		}
		// RE2 caps match length; longer scan windows are fine but bound runaway.
		re.Longest()
		kws := make([]string, 0, len(r.Keywords))
		for _, k := range r.Keywords {
			kws = append(kws, strings.ToLower(k))
		}
		sev := strings.ToLower(r.Severity)
		if sev == "" {
			sev = "medium"
		}
		rules = append(rules, Rule{
			ID:         r.ID,
			Name:       r.Name,
			Severity:   sev,
			Category:   r.Category,
			Keywords:   kws,
			EntropyMin: r.EntropyMin,
			re:         re,
		})
		seen[r.ID] = true
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no usable detector rules")
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "[i] %d detector rule(s) skipped, %d active\n", skipped, len(rules))
	}
	return rules, nil
}

// matchRules scans a text blob and returns findings. lineIndex maps byte
// offsets to (line, column). decoder labels the origin ("" = raw content).
func matchRules(rules []Rule, content []byte, li *lineIndex, decoder string) []Finding {
	lower := toLowerASCII(content)
	var out []Finding
	for i := range rules {
		r := &rules[i]
		if !keywordHit(lower, r.Keywords) {
			continue
		}
		matches := r.re.FindAllSubmatchIndex(content, 64)
		for _, m := range matches {
			// Prefer capture group 1 as the secret; else the whole match.
			ss, se := m[0], m[1]
			if len(m) >= 4 && m[2] >= 0 {
				ss, se = m[2], m[3]
			}
			if ss < 0 || se <= ss {
				continue
			}
			secret := string(content[ss:se])
			ent := shannonEntropy(secret)
			if r.EntropyMin > 0 && ent < r.EntropyMin {
				continue
			}
			if isFalsePositive(secret, r) {
				continue
			}
			line, col := li.at(m[0])
			full := string(content[m[0]:m[1]])
			out = append(out, Finding{
				RuleID:     r.ID,
				RuleName:   r.Name,
				Severity:   r.Severity,
				Category:   r.Category,
				Line:       line,
				Column:     col,
				Match:      collapse(full), // redaction applied later unless --show-secrets
				Secret:     secret,
				Entropy:    round2(ent),
				ViaDecoder: decoder,
			})
		}
	}
	return out
}

func round2(f float64) float64 { return float64(int(f*100+0.5)) / 100 }
