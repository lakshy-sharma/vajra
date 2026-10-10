// internal/scanner/yara/match.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package yara

import (
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

// ConvertMatches translates raw go-yara results into our model type
// and wraps them as Match values for severity classification.
func ConvertMatches(raw yara.MatchRules) []Match {
	out := make([]Match, 0, len(raw))
	for _, m := range raw {
		strs := make([]string, 0, len(m.Strings))
		for _, s := range m.Strings {
			strs = append(strs, string(s.Data))
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
