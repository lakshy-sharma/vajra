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
//	APT_*, MALWARE_*, MAL_*   → CRITICAL (known malware / APT)
//	Ransomware*                → CRITICAL (data destruction risk)
//	Exploit*, EXPL_*, HKTL_*  → HIGH     (exploitation / hacktools)
//	SUSP_*                     → MEDIUM   (suspicious indicator)
//	3+ matches (any prefix)    → HIGH     (correlated hit)
//	1-2 matches                → MEDIUM
//	0 matches                  → CLEAN
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
		if hasPrefix(m.Rule, "MALWARE_") {
			return models.SeverityCritical
		}
		if hasPrefix(m.Rule, "MAL_") {
			return models.SeverityCritical
		}
		if hasPrefix(m.Rule, "Exploit") {
			return models.SeverityHigh
		}
		if hasPrefix(m.Rule, "EXPL_") {
			return models.SeverityHigh
		}
		if hasPrefix(m.Rule, "HKTL_") {
			return models.SeverityHigh
		}
		if hasPrefix(m.Rule, "SUSP_") {
			return models.SeverityMedium
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
