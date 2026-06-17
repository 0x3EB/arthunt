package scan

import "testing"

// Each entry: a realistic positive sample that the named rule MUST detect.
// Guards against tightening a regex/entropy/keyword into never matching.
var truePositives = []struct {
	rule    string
	content string
}{
	{"private-key", dec("LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnoKLS0tLS1FTkQgT1BFTlNTSCBQUklWQVRFIEtFWS0tLS0t")},
	{"aws-access-key-id", dec("YXdzLmFjY2Vzc0tleUlkPUFLSUFaOFlRM1JYTk8yV0s0UDFD")},
	{"aws-secret-access-key", dec("YXdzX3NlY3JldF9hY2Nlc3Nfa2V5ID0gIktxM3hWMmJONW1QOHRMMWRGNmhKOXNRNGNSMGdFN3VXblpyN3lBMkJjIg==")},
	{"gcp-api-key", dec("a2V5OiBBSXphU3lBMWMzRDRlNUY2ZzdIOGk5SjBrTG1Ob1BxUnNUdVZ3WHk=")},
	{"github-pat", dec("dG9rZW49Z2hwX2FCM3hZWmNkV1gzNGVmR0g1NmlqS0w3OG1uUFE5MHJzVFZ3Wg==")},
	{"gitlab-pat", dec("R0lUTEFCX1RPS0VOPWdscGF0LWFCM3hZWmNkV1gzNGVmR0g1Nmlq")},
	{"slack-token", dec("c2xhY2s9eG94Yi1hQmNEZUYtZ0hpSmtMLW1Ob1BxUnNUdVZ3WHlaYWJjZGVm")},
	{"stripe-secret", dec("c3RyaXBlPXNrX2xpdmVfYUJjRGVGZ0hpSmtMbU5vUHFSc1R1VndY")},
	{"sendgrid", dec("U0cuYUJjRGVGZ0hpSmtMbU5vUHFSc1R1Vi5hQmNEZUZnSGlKa0xtTm9QcVJzVHVWd1h5WmFCY0RlRmdIaUprTG1Ob1Bx")},
	{"npm-token", dec("Ly9yZWdpc3RyeS86X2F1dGhUb2tlbj1ucG1fYUIzeFlaY2RXWDM0ZWZHSDU2aWpLTDc4bW5QUTkwcnNUVnda")},
	{"npmrc-authtoken", "//registry.npmjs.org/:_authToken=aB3xYZcdWX34efGH56ijKL"},
	{"docker-auth", `"auth": "dXNlcjpzdXBlcnNlY3JldHBhc3N3b3Jk"`},
	{"db-conn-postgres", "postgres://app:Sup3rS3cretPw@db.internal:5432/prod"},
	{"basic-auth-url", "https://admin:Tr0ub4dourPlus@internal.example.com/git"},
	{"twilio-sid", dec("dHdpbGlvX2F1dGg6IEFDYTFiMmMzZDRlNWY2YTdiOGM5ZDBlMWYyYTNiNGM1ZDY=")},
	{"mailgun", dec("bWFpbGd1bl9rZXkgPSBrZXktOWY4NmQwODE4ODRjN2Q2NTlhMmZlYWEwYzU1YWQwMTU=")},
	{"pagerduty", `pagerduty_token = "uK7p2QmZ9rT4wX1nB6vC"`},
	{"openai-project", dec("T1BFTkFJPXNrLXByb2otYUIzeFlaY2RXWDM0ZWZHSDU2aWpLTDc4bW5QUTkwcnNUVndaMDEyMzQ1")},
	{"anthropic", dec("QU5USFJPUElDX0FQSV9LRVk9c2stYW50LWFCM3hZWmNkV1gzNGVmR0g1NmlqS0w3OG1uUFE5MA==")},
	{"jwt", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ_kR8mP2nT7vL"},
	{"generic-secret-assign", `client_secret = "aB3xYZcdWX34efGH56ijKLmnOp"`},
	{"generic-high-entropy-hex", "hmac_secret = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822c"},
	{"jfrog-access-token", dec("dG9rZW49ZXlKMlpYSWlPaUl5SWl3aWRIbHdJam9pU2xkVUlpd2lZV3huSWpvaVVsTXlOVFlpZlEuZXlKemRXSWlPaUpoWW1NaWZRLnNpZ25hdHVyZV9hYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")},
	{"hashicorp-vault-service-token", dec("VkFVTFRfVE9LRU49aHZzLkNBRVNJSjAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ekFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMDEyMzQ1Njc4")},
	{"snowflake-token-context", `snowflake_password = "Sn0wFl@ke_Secret_2026X"`},
	{"databricks-api-token", dec("REFUQUJSSUNLU19UT0tFTj1kYXBpMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")},
	{"new-relic-user-api-key", dec("TkVXX1JFTElDX0FQSV9LRVk9TlJBSy1BMUIyQzNENEU1RjZHN0g4SjlLMEwxTTJOM1A=")},
}

func TestTruePositivesFire(t *testing.T) {
	rules, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range truePositives {
		content := []byte(tc.content)
		fs := matchRules(rules, content, newLineIndex(content), "")
		hit := false
		for _, f := range fs {
			if f.RuleID == tc.rule {
				hit = true
				break
			}
		}
		if !hit {
			got := ""
			for _, f := range fs {
				got += f.RuleID + " "
			}
			t.Errorf("rule %q FAILED to fire on %q (matched instead: [%s])", tc.rule, tc.content, got)
		}
	}
}
