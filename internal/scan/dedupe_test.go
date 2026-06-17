package scan

import "testing"

func TestDedupeBySecret(t *testing.T) {
	mk := func(rule, cat, sev, secret string, line int) Finding {
		return Finding{RuleID: rule, Category: cat, Severity: sev, Secret: secret, Repo: "r", Path: "p", Line: line}
	}

	// Same secret at same spot: a specific critical rule must beat a generic medium.
	out := dedupeBySecret([]Finding{
		mk("generic-secret-assign", "generic", "medium", "S3CR3T", 1),
		mk("stripe-secret", "saas", "critical", "S3CR3T", 1),
	})
	if len(out) != 1 || out[0].RuleID != "stripe-secret" {
		t.Fatalf("expected single stripe-secret, got %+v", out)
	}

	// Dedup must NEVER downgrade: a generic HIGH outranks a specific LOW.
	out = dedupeBySecret([]Finding{
		mk("twilio-sid", "saas", "low", "ABC123", 2),
		mk("generic-secret-assign", "generic", "high", "ABC123", 2),
	})
	if len(out) != 1 || out[0].Severity != "high" {
		t.Fatalf("dedup downgraded severity: %+v", out)
	}

	// Equal severity: the specific (non-generic) rule wins the tie.
	out = dedupeBySecret([]Finding{
		mk("generic-secret-assign", "generic", "high", "XYZ", 3),
		mk("github-pat", "vcs", "high", "XYZ", 3),
	})
	if len(out) != 1 || out[0].RuleID != "github-pat" {
		t.Fatalf("expected github-pat to win tie, got %+v", out)
	}

	// Distinct secrets are never merged.
	out = dedupeBySecret([]Finding{
		mk("github-pat", "vcs", "high", "AAA", 1),
		mk("github-pat", "vcs", "high", "BBB", 1),
	})
	if len(out) != 2 {
		t.Fatalf("distinct secrets merged: %+v", out)
	}
}
