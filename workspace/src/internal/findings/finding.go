// internal/findings/finding.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package findings

import "vajra/shared/models"

// Source identifies which detection component produced a finding.
type Source string

const (
	SourceFileScanner    Source = "file_scanner"
	SourceProcessScanner Source = "process_scanner"
	SourceDupWatcher     Source = "dup_watcher"
	SourceAutorunScanner Source = "autorun_scanner"
	SourceSecretsScanner Source = "secrets_scanner"
	SourceFullScan       Source = "full_scan"
)

// Finding is the unified detection output produced by every watcher
// and scanner. FindingWriter is the only component that writes to
// the detections table — all detection sources produce a Finding
// and hand it off, never writing to DB directly.
type Finding struct {
	Source     Source
	Severity   models.EventSeverity
	Status     models.EventStatus
	MachineID  string
	DetectedAt int64 // Unix timestamp

	// Process context — zero values when not applicable.
	PID         uint32
	PPID        uint32
	UID         uint32
	GID         uint32
	EUID        uint32
	EGID        uint32
	ProcessName string
	ExePath     string
	CmdLine     string
	CWD         string

	// Detection detail.
	TargetPath string // file path, script path, or persistence location
	RuleID     string // first matching rule name — used for dedup key
	Notes      string

	// Artifacts — populated depending on source.
	FileHash    string
	FileSize    int64
	YaraMatches []models.YaraMatch

	// Network detail — populated by DupWatcher.
	RemoteAddr  string
	RemotePort  uint16
	Protocol    string
	SocketInode uint64

	// Secret detail — populated by SecretsScanner.
	SecretRuleID      string
	SecretHash        string // sha256(secret) — never the value itself
	SecretFingerprint string // betterleaks match fingerprint for ignore list
	SecretStartLine   int
	SecretEndLine     int
	SecretContext     string // surrounding line with secret redacted
	// Extension — arbitrary key/value for future fields.
	// Avoids schema migrations for source-specific detail that
	// doesn't warrant a dedicated column.
	Extensions map[string]string
}
