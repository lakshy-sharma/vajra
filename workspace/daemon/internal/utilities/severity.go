// internal/utilities/severity.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package utilities

import "vajra/shared/models"

// RuleMatch is the minimal interface any scanning engine must implement
// to participate in severity classification. YARA, betterleaks, and hash
// lookups all produce matches — severity classification is engine-agnostic.
type RuleMatch interface {
	RuleID() string
	RuleTags() []string
}

// ClassifySeverity returns the highest severity implied by a set of rule
// matches. Rule naming follows YARA Forge conventions which we adopt as
// the shared vocabulary across all engines.
//
// Prefix hierarchy (first match wins per rule):
//
//	APT_, MALWARE_, MAL_, Ransomware → CRITICAL
//	HKTL_, Exploit, EXPL_            → HIGH
//	SUSP_                             → MEDIUM
//	3+ matches with no prefix match  → HIGH (correlated signal)
//	1–2 matches with no prefix match → MEDIUM
//	0 matches                         → CLEAN
func ClassifySeverity(matches []RuleMatch) models.EventSeverity {
	if len(matches) == 0 {
		return models.SeverityClean
	}

	for _, m := range matches {
		id := m.RuleID()
		switch {
		case hasPrefix(id, "APT_"),
			hasPrefix(id, "MALWARE_"),
			hasPrefix(id, "MAL_"),
			hasPrefix(id, "Ransomware"):
			return models.SeverityCritical
		case hasPrefix(id, "HKTL_"),
			hasPrefix(id, "Exploit"),
			hasPrefix(id, "EXPL_"):
			return models.SeverityHigh
		case hasPrefix(id, "SUSP_"):
			return models.SeverityMedium
		}
	}

	if len(matches) >= 3 {
		return models.SeverityHigh
	}
	return models.SeverityMedium
}

// hasPrefix is a bounds-safe prefix check without importing strings.
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
