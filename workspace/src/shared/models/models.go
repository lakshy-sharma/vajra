// shared/models/models.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package models

// EventSeverity represents the severity level of a security event.
type EventSeverity string

const (
	SeverityClean    EventSeverity = "CLEAN"
	SeverityLow      EventSeverity = "LOW"
	SeverityMedium   EventSeverity = "MEDIUM"
	SeverityHigh     EventSeverity = "HIGH"
	SeverityCritical EventSeverity = "CRITICAL"
)

// EventStatus represents the handling status of an event.
type EventStatus string

const (
	StatusNew        EventStatus = "NEW"
	StatusInProgress EventStatus = "IN_PROGRESS"
	StatusResolved   EventStatus = "RESOLVED"
	StatusIgnored    EventStatus = "IGNORED"
)

// AutorunCategory represents the persistence mechanism type.
type AutorunCategory string

// Add these category constants — sources_linux.go uses all of them
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

// UniqueKey returns a stable string key for deduplication.
// Prefers SHA256 when available; falls back to composite key.
func (e *AutorunEntry) UniqueKey() string {
	if e.SHA256 != "" {
		return e.SHA256
	}
	return string(e.Category) + "|" + e.Location + "|" + e.ImagePath
}

// YaraMatch represents a single YARA rule match.
type YaraMatch struct {
	Rule      string   `json:"rule"`
	Namespace string   `json:"namespace"`
	Tags      []string `json:"tags"`
	Strings   []string `json:"strings,omitempty"`
}

// FileScanResult represents a file scan result.
type FileScanResult struct {
	ID          int64
	ScanTime    int64
	FilePath    string
	FileSize    int64
	FileHash    string
	YaraMatches []YaraMatch
	Severity    EventSeverity
	Status      EventStatus
	EventType   uint32
	TriggerPID  uint32
	TriggerUID  uint32
	TriggerComm string
	Notes       string
	CreatedAt   string
	UpdatedAt   string
}

// ProcessScanResult represents a process scan result.
type ProcessScanResult struct {
	ID          int64
	ScanTime    int64
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
	YaraMatches []YaraMatch
	Severity    EventSeverity
	Status      EventStatus
	EventType   uint32
	Notes       string
	CreatedAt   string
	UpdatedAt   string
}

// NetworkEvent replaces NetworkEventRecord
type NetworkEvent struct {
	ID          int64
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

// MemoryEvent replaces MemoryEventRecord
type MemoryEvent struct {
	ID          int64
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

// SecurityEvent replaces SecurityEventRecord
type SecurityEvent struct {
	ID          int64
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

// AutorunEntry represents a single persistence/autorun record.
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

// QuarantinedFile represents a file that has been quarantined.
type QuarantinedFile struct {
	ID             int64
	OriginalPath   string
	QuarantinePath string
	FileHash       string
	FileSize       int64
	QuarantineTime int64
	RelatedScanID  int64
	Severity       EventSeverity
	Reason         string
	Restored       bool
	RestoredTime   int64
	Notes          string
	CreatedAt      string
}

// EventStatistic represents aggregated daily event counts.
type EventStatistic struct {
	ID             int64
	Date           string // YYYY-MM-DD
	EventType      uint32
	EventName      string
	TotalCount     int64
	MaliciousCount int64
	CleanCount     int64
}
