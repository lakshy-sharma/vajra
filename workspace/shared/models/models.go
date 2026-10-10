// shared/models/models.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package models

type EventSeverity string

const (
	SeverityClean    EventSeverity = "CLEAN"
	SeverityLow      EventSeverity = "LOW"
	SeverityMedium   EventSeverity = "MEDIUM"
	SeverityHigh     EventSeverity = "HIGH"
	SeverityCritical EventSeverity = "CRITICAL"
)

type EventStatus string

const (
	StatusNew        EventStatus = "NEW"
	StatusInProgress EventStatus = "IN_PROGRESS"
	StatusResolved   EventStatus = "RESOLVED"
	StatusIgnored    EventStatus = "IGNORED"
)

type AutorunCategory string

const (
	CategorySystemdSystem AutorunCategory = "systemd_system"
	CategorySystemdUser   AutorunCategory = "systemd_user"
	CategorySystemdTimer  AutorunCategory = "systemd_timer"
	CategoryCronSystem    AutorunCategory = "cron_system"
	CategoryCronUser      AutorunCategory = "cron_user"
	CategoryShellProfile  AutorunCategory = "shell_profile"
	CategorySysVInit      AutorunCategory = "sysv_init"
	CategoryXDGAutostart  AutorunCategory = "xdg_autostart"
	CategoryDBus          AutorunCategory = "dbus"
	CategoryAtJob         AutorunCategory = "at_job"
	CategoryAnacron       AutorunCategory = "anacron"
	CategoryLDPreload     AutorunCategory = "ld_preload"
	CategoryPAM           AutorunCategory = "pam"
)

func (e *AutorunEntry) UniqueKey() string {
	if e.SHA256 != "" {
		return e.SHA256
	}
	return string(e.Category) + "|" + e.Location + "|" + e.ImagePath
}

type YaraMatch struct {
	Rule      string   `json:"rule"`
	Namespace string   `json:"namespace"`
	Tags      []string `json:"tags"`
	Strings   []string `json:"strings,omitempty"`
}

// ── Unified detection ─────────────────────────────────────────

// Detection is the unified record written by FindingWriter for every
// non-clean finding regardless of source. The UI, sync, and response
// system all reference this table — not per-source tables.
type Detection struct {
	ID            int64
	MachineID     string
	DetectionTime int64
	Source        string
	Severity      EventSeverity
	Status        EventStatus

	// Process context — zero when not applicable.
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

	TargetPath     string
	RuleID         string
	MITRETechnique string
	Notes          string
	DedupCount     uint64
	CreatedAt      string
	UpdatedAt      string
}

// DetectionArtifact holds file hash and YARA matches for detections
// that involve file content analysis. Separated to avoid nulls on
// detections that have no file content (e.g. reverse shell, secrets).
type DetectionArtifact struct {
	ID          int64
	DetectionID int64
	FileHash    string
	FileSize    int64
	YaraMatches []YaraMatch
}

// DetectionNetwork holds socket details for reverse shell detections.
type DetectionNetwork struct {
	ID          int64
	DetectionID int64
	RemoteAddr  string
	RemotePort  uint16
	Protocol    string
	SocketInode uint64
	OldFd       uint32
	NewFd       uint32
}

// DetectionSecret holds betterleaks finding detail.
// SecretHash is sha256(secret) — the raw value is never stored.
// Fingerprint is the betterleaks-computed match fingerprint used
// to suppress known false positives via WithIgnoredFingerprints.
type DetectionSecret struct {
	ID           int64
	DetectionID  int64
	RuleID       string
	SecretHash   string
	Fingerprint  string
	StartLine    int
	EndLine      int
	MatchContext string // surrounding line with secret redacted
}

// DetectionExtension is one key/value pair attached to a detection.
// Used as a forward-compatible escape hatch for source-specific fields
// that don't warrant a dedicated column. Each key gets its own row
// so searches on key+value are index-assisted.
type DetectionExtension struct {
	ID          int64
	DetectionID int64
	Key         string
	Value       string
}

// EvidenceSnapshot captures live process state at the moment a
// HIGH or CRITICAL detection fires. Process state goes stale within
// seconds — the collector runs immediately on detection.
type EvidenceSnapshot struct {
	ID          int64
	DetectionID int64
	CapturedAt  int64
	OpenFDs     string // JSON — /proc/PID/fd/* symlink targets
	Maps        string // JSON — /proc/PID/maps entries
	Environ     string // JSON — /proc/PID/environ key/value pairs
	Status      string // raw /proc/PID/status content
}

// AuditLog records component lifecycle and health events.
// Append-only — never updated or deleted by retention cleanup.
type AuditLog struct {
	ID        int64
	MachineID string
	LoggedAt  int64
	Component string
	EventType string // 'startup', 'shutdown', 'scan_completed',
	// 'rules_updated', 'health_check', 'error'
	Status         string // 'ok', 'warn', 'error'
	Details        string // JSON — component-specific metrics
	DurationMS     int64
	ItemsProcessed int64
}

// ── Raw telemetry ─────────────────────────────────────────────
// These tables record all kernel events including noise.
// They feed the Sigma engine and behavioral correlation server-side.
// Detection tables above hold only non-clean findings.

type NetworkEvent struct {
	ID          int64
	MachineID   string
	EventTime   int64
	EventType   uint32
	PID         uint32
	UID         uint32
	ProcessName string
	SrcAddr     string
	DstAddr     string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string
	Severity    EventSeverity
	Status      EventStatus
	Notes       string
	CreatedAt   string
}

type MemoryEvent struct {
	ID          int64
	MachineID   string
	EventTime   int64
	EventType   uint32
	PID         uint32
	UID         uint32
	ProcessName string
	Address     uint64
	Length      uint64
	Protection  uint32
	Flags       uint32
	FilePath    string
	Severity    EventSeverity
	Status      EventStatus
	Notes       string
	CreatedAt   string
}

type SecurityEvent struct {
	ID          int64
	MachineID   string
	EventTime   int64
	EventType   uint32
	EventName   string
	PID         uint32
	UID         uint32
	ProcessName string
	TargetPID   uint32
	TargetPath  string
	Details     string
	Severity    EventSeverity
	Status      EventStatus
	YaraMatches []YaraMatch
	ActionTaken string
	Notes       string
	CreatedAt   string
	UpdatedAt   string
}

// ── Inventory ─────────────────────────────────────────────────

type AutorunEntry struct {
	ID        int64
	Category  AutorunCategory
	Location  string
	ImagePath string
	ImageName string
	Arguments string
	MD5       string
	SHA1      string
	SHA256    string
	IsActive  bool
	FirstSeen int64
	LastSeen  int64
	CreatedAt string
	UpdatedAt string
}

type QuarantinedFile struct {
	ID             int64
	OriginalPath   string
	QuarantinePath string
	FileHash       string
	FileSize       int64
	QuarantineTime int64
	RelatedID      int64 // FK → detections.id
	Severity       EventSeverity
	Reason         string
	Restored       bool
	RestoredTime   int64
	Notes          string
	CreatedAt      string
}

// ── Aggregation ───────────────────────────────────────────────

type EventStatistic struct {
	ID             int64
	Date           string
	EventType      uint32
	EventName      string
	TotalCount     int64
	MaliciousCount int64
	CleanCount     int64
}

// ── Process tree ──────────────────────────────────────────────

// ProcessTreeEntry is one row in the process_tree adjacency list.
// Written on every execve regardless of scan outcome.
type ProcessTreeEntry struct {
	ID        int64
	MachineID string
	PID       uint32
	PPID      uint32
	Comm      string
	ExePath   string
	CmdLine   string
	EventTime int64
}
