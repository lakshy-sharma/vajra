// internal/scanner/yara/match.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package yara

import (
	"encoding/hex"

	"github.com/hillu/go-yara/v4"
	"vajra/shared/models"
)

// Match wraps models.YaraMatch to implement utilities.RuleMatch,
// letting YARA findings participate in engine-agnostic severity
// classification without a dependency on the YARA library in utilities.
type Match struct {
	models.YaraMatch
}

func (m Match) RuleID() string     { return m.Rule }
func (m Match) RuleTags() []string { return m.Tags }

// ConvertMatches translates raw go-yara results into our model type.
// snapshotBytes controls the maximum number of match bytes captured as
// a hex snapshot — comes from ScanSettings.YaraSnapshotBytes in config.
//
// E8: the previous implementation built []string losing the identifier and
// offset. YaraStringMatch preserves all three forensic fields.
func ConvertMatches(raw yara.MatchRules, snapshotBytes int) []Match {
	if snapshotBytes <= 0 {
		snapshotBytes = 128
	}
	out := make([]Match, 0, len(raw))
	for _, m := range raw {
		strs := make([]models.YaraStringMatch, 0, len(m.Strings))
		for _, s := range m.Strings {
			snap := s.Data
			if len(snap) > snapshotBytes {
				snap = snap[:snapshotBytes]
			}
			strs = append(strs, models.YaraStringMatch{
				Identifier:  s.Name,
				Offset:      uint64(s.Offset),
				SnapshotHex: hex.EncodeToString(snap),
			})
		}
		out = append(out, Match{
			YaraMatch: models.YaraMatch{
				Rule:      m.Rule,
				Namespace: m.Namespace,
				Tags:      m.Tags,
				Strings:   strs,
			},
		})
	}
	return out
}

// ToModelMatches extracts the underlying models.YaraMatch slice
// from a []Match for storage in the DB.
func ToModelMatches(matches []Match) []models.YaraMatch {
	out := make([]models.YaraMatch, len(matches))
	for i, m := range matches {
		out[i] = m.YaraMatch
	}
	return out
}
