// shared/models/models.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

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
	CategoryLDPreload     AutorunCategory = "ld_preload"
	CategoryPAM           AutorunCategory = "pam"
	CategoryDesktopEntry  AutorunCategory = "desktop_entry"
	CategorySysVInit      AutorunCategory = "sysv_init"
	CategoryXDGAutostart  AutorunCategory = "xdg_autostart"
	CategoryKernelModule  AutorunCategory = "kernel_module"
	CategoryUdevRule      AutorunCategory = "udev_rule"
	CategoryDBus          AutorunCategory = "dbus"
	CategoryAtJob         AutorunCategory = "at_job"
	CategoryAnacron       AutorunCategory = "anacron"
)

type YaraStringMatch struct {
	Identifier  string `json:"identifier"`
	Offset      uint64 `json:"offset"`
	SnapshotHex string `json:"snapshot_hex"`
}

type YaraMatch struct {
	Rule      string            `json:"rule"`
	Namespace string            `json:"namespace"`
	Tags      []string          `json:"tags"`
	Strings   []YaraStringMatch `json:"strings,omitempty"`
}

type Detection struct {
	ID             int64         `json:"id"`
	MachineID      string        `json:"machine_id"`
	DetectionTime  int64         `json:"detection_time"`
	Source         string        `json:"source"`
	Severity       EventSeverity `json:"severity"`
	Status         EventStatus   `json:"status"`
	PID            uint32        `json:"pid"`
	PPID           uint32        `json:"ppid"`
	UID            uint32        `json:"uid"`
	GID            uint32        `json:"gid"`
	EUID           uint32        `json:"euid"`
	EGID           uint32        `json:"egid"`
	ProcessName    string        `json:"process_name"`
	ExePath        string        `json:"exe_path"`
	CmdLine        string        `json:"cmd_line"`
	CWD            string        `json:"cwd"`
	TargetPath     string        `json:"target_path"`
	RuleID         string        `json:"rule_id"`
	MITRETechnique string        `json:"mitre_technique"`
	DedupCount     uint64        `json:"dedup_count"`
	Notes          string        `json:"notes"`
	CreatedAt      int64         `json:"created_at"`
	UpdatedAt      int64         `json:"updated_at"`
}

type DetectionArtifact struct {
	ID          int64       `json:"id"`
	DetectionID int64       `json:"detection_id"`
	FileHash    string      `json:"file_hash"`
	FileSize    int64       `json:"file_size"`
	YaraMatches []YaraMatch `json:"yara_matches"`
}

type DetectionNetwork struct {
	ID          int64  `json:"id"`
	DetectionID int64  `json:"detection_id"`
	RemoteAddr  string `json:"remote_addr"`
	RemotePort  uint16 `json:"remote_port"`
	Protocol    string `json:"protocol"`
	SocketInode uint64 `json:"socket_inode"`
	OldFd       int32  `json:"old_fd"` // dup2/dup3 source fd — signed to match kernel syscall ABI
	NewFd       int32  `json:"new_fd"` // dup2/dup3 destination stdio fd (0/1/2)
}

type DetectionExtension struct {
	ID          int64  `json:"id"`
	DetectionID int64  `json:"detection_id"`
	Key         string `json:"key"`
	Value       string `json:"value"`
}

type DetectionSecret struct {
	ID           int64  `json:"id"`
	DetectionID  int64  `json:"detection_id"`
	RuleID       string `json:"rule_id"`
	SecretHash   string `json:"secret_hash"`
	Fingerprint  string `json:"fingerprint"`
	StartLine    int    `json:"start_line"`
	EndLine      int    `json:"end_line"`
	MatchContext string `json:"match_context"`
}

type EvidenceSnapshot struct {
	ID          int64           `json:"id"`
	DetectionID int64           `json:"detection_id"`
	CapturedAt  int64           `json:"captured_at"`
	OpenFDs     json.RawMessage `json:"open_fds"`
	Maps        json.RawMessage `json:"maps"`
	Environ     json.RawMessage `json:"environ"`
	Status      string          `json:"status"`
}

type SecurityEvent struct {
	ID          int64         `json:"id"`
	MachineID   string        `json:"machine_id"`
	EventTime   int64         `json:"event_time"`
	EventType   uint32        `json:"event_type"`
	EventName   string        `json:"event_name"`
	PID         uint32        `json:"pid"`
	UID         uint32        `json:"uid"`
	ProcessName string        `json:"process_name"`
	TargetPID   uint32        `json:"target_pid"`
	TargetPath  string        `json:"target_path"`
	Details     string        `json:"details"`
	Severity    EventSeverity `json:"severity"`
	Status      EventStatus   `json:"status"`
	ActionTaken string        `json:"action_taken"`
	Notes       string        `json:"notes"`
	CreatedAt   int64         `json:"created_at"`
	UpdatedAt   int64         `json:"updated_at"`
}

type NetworkEvent struct {
	ID          int64         `json:"id"`
	MachineID   string        `json:"machine_id"`
	EventTime   int64         `json:"event_time"`
	EventType   uint32        `json:"event_type"`
	PID         uint32        `json:"pid"`
	UID         uint32        `json:"uid"`
	ProcessName string        `json:"process_name"`
	SrcAddr     string        `json:"src_addr"`
	DstAddr     string        `json:"dst_addr"`
	SrcPort     uint16        `json:"src_port"`
	DstPort     uint16        `json:"dst_port"`
	Protocol    string        `json:"protocol"`
	Severity    EventSeverity `json:"severity"`
	Status      EventStatus   `json:"status"`
	Notes       string        `json:"notes"`
	CreatedAt   int64         `json:"created_at"`
	UpdatedAt   int64         `json:"updated_at"`
}

type MemoryEvent struct {
	ID          int64         `json:"id"`
	MachineID   string        `json:"machine_id"`
	EventTime   int64         `json:"event_time"`
	EventType   uint32        `json:"event_type"`
	PID         uint32        `json:"pid"`
	UID         uint32        `json:"uid"`
	ProcessName string        `json:"process_name"`
	Address     uint64        `json:"address"`
	Length      uint64        `json:"length"`
	Protection  uint32        `json:"protection"`
	Flags       uint32        `json:"flags"`
	FilePath    string        `json:"file_path"`
	Severity    EventSeverity `json:"severity"`
	Status      EventStatus   `json:"status"`
	Notes       string        `json:"notes"`
	CreatedAt   int64         `json:"created_at"`
	UpdatedAt   int64         `json:"updated_at"`
}

type ProcessTreeEntry struct {
	ID        int64  `json:"id"`
	MachineID string `json:"machine_id"`
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	Comm      string `json:"comm"`
	ExePath   string `json:"exe_path"`
	CmdLine   string `json:"cmd_line"`
	EventTime int64  `json:"event_time"`
	CreatedAt int64  `json:"created_at"`
}

type AutorunEntry struct {
	ID        int64           `json:"id"`
	MachineID string          `json:"machine_id"`
	Category  AutorunCategory `json:"category"`
	Location  string          `json:"location"`
	ImagePath string          `json:"image_path"`
	ImageName string          `json:"image_name"`
	Arguments string          `json:"arguments"`
	SHA256    string          `json:"sha256"`
	IsActive  bool            `json:"is_active"`
	FirstSeen int64           `json:"first_seen"`
	LastSeen  int64           `json:"last_seen"`
	CreatedAt int64           `json:"created_at"`
	UpdatedAt int64           `json:"updated_at"`
}

// UniqueKey returns a stable identity key for deduplication against DB state.
// Null-byte separators prevent category+location+path tuple collisions.
func (e *AutorunEntry) UniqueKey() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s", e.Category, e.Location, e.ImagePath)
	return hex.EncodeToString(h.Sum(nil))
}

type EventStatistic struct {
	ID             int64  `json:"id"`
	Date           int64  `json:"date"`
	EventType      uint32 `json:"event_type"`
	EventName      string `json:"event_name"`
	TotalCount     int64  `json:"total_count"`
	MaliciousCount int64  `json:"malicious_count"`
	CleanCount     int64  `json:"clean_count"`
}

type AuditLog struct {
	ID             int64  `json:"id"`
	MachineID      string `json:"machine_id"`
	LoggedAt       int64  `json:"logged_at"`
	Component      string `json:"component"`
	EventType      string `json:"event_type"`
	Status         string `json:"status"`
	Details        string `json:"details"`
	DurationMS     int64  `json:"duration_ms"`
	ItemsProcessed int64  `json:"items_processed"`
}

type AppConfig struct {
	ID            int64  `json:"id"`
	ConfigJSON    string `json:"config_json"`
	SchemaVersion int    `json:"schema_version"`
	YAMLPath      string `json:"yaml_path"`
	UpdatedAt     int64  `json:"updated_at"`
}
