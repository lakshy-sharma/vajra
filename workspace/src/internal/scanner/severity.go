// internal/scanner/severity.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package scanner

import (
	"vajra/shared/models"
)

// ClassifyYARASeverity maps YARA match results to an EventSeverity.
// Rules are checked in priority order — first match at a given
// level wins. Rule-name prefix conventions:
//
//	APT_*        → CRITICAL (nation-state / advanced threat)
//	Ransomware*  → CRITICAL (data destruction risk)
//	Exploit*     → HIGH     (active exploitation attempt)
//	3+ matches   → HIGH     (correlated multi-rule hit)
//	1-2 matches  → MEDIUM   (single indicator)
//	0 matches    → CLEAN
//
// This function is the single place severity logic lives.
// Both filescanner and processscanner use it. When the
// Analyzer interface is added, this becomes one step in the
// pipeline and can be extended without touching job code.
func ClassifyYARASeverity(matches []models.YaraMatch) models.EventSeverity {
	if len(matches) == 0 {
		return models.SeverityClean
	}

	for _, m := range matches {
		if hasPrefix(m.Rule, "APT_") {
			return models.SeverityCritical
		}
		if hasPrefix(m.Rule, "Ransomware") {
			return models.SeverityCritical
		}
		if hasPrefix(m.Rule, "Exploit") {
			return models.SeverityHigh
		}
	}

	if len(matches) >= 3 {
		return models.SeverityHigh
	}

	return models.SeverityMedium
}

// hasPrefix is a bounds-safe prefix check that avoids
// importing strings just for this one use case.
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
