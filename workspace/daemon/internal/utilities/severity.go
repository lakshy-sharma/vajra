// internal/utilities/severity.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package utilities

import (
	"strings"

	"vajra/shared/models"
)

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
		case strings.HasPrefix(id, "APT_"),
			strings.HasPrefix(id, "MALWARE_"),
			strings.HasPrefix(id, "MAL_"),
			strings.HasPrefix(id, "Ransomware"):
			return models.SeverityCritical
		case strings.HasPrefix(id, "HKTL_"),
			strings.HasPrefix(id, "Exploit"),
			strings.HasPrefix(id, "EXPL_"):
			return models.SeverityHigh
		case strings.HasPrefix(id, "SUSP_"):
			return models.SeverityMedium
		}
	}

	if len(matches) >= 3 {
		return models.SeverityHigh
	}
	return models.SeverityMedium
}

// SeverityRank returns a numeric rank for severity comparison.
// Higher values are more severe. Used by analyzers to merge multiple results
// without importing the full analyzer package.
func SeverityRank(s models.EventSeverity) int {
	switch s {
	case models.SeverityClean:
		return 0
	case models.SeverityLow:
		return 1
	case models.SeverityMedium:
		return 2
	case models.SeverityHigh:
		return 3
	case models.SeverityCritical:
		return 4
	default:
		return 0
	}
}
