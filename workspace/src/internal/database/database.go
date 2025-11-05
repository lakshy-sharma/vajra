package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"vajra/internal/utilities"

	"github.com/hillu/go-yara/v4"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
)

var (
	DB *sql.DB
)

// EventSeverity represents the severity level of a security event
type EventSeverity string

const (
	SeverityClean    EventSeverity = "CLEAN"
	SeverityLow      EventSeverity = "LOW"
	SeverityMedium   EventSeverity = "MEDIUM"
	SeverityHigh     EventSeverity = "HIGH"
	SeverityCritical EventSeverity = "CRITICAL"
)

// EventStatus represents the handling status of an event
type EventStatus string

const (
	StatusNew        EventStatus = "NEW"
	StatusInProgress EventStatus = "IN_PROGRESS"
	StatusResolved   EventStatus = "RESOLVED"
	StatusIgnored    EventStatus = "IGNORED"
)

// FileScanResult represents a file scan result for database storage
type FileScanResult struct {
	ID          int64
	ScanTime    int64
	FilePath    string
	FileSize    int64
	FileHash    string // SHA256 hash
	YaraMatches []YaraMatchRecord
	Severity    EventSeverity
	Status      EventStatus
	EventType   uint32 // From eBPF event type
	TriggerPID  uint32
	TriggerUID  uint32
	TriggerComm string
	Notes       string
}

// ProcessScanResult represents a process scan result
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
	YaraMatches []YaraMatchRecord
	Severity    EventSeverity
	Status      EventStatus
	EventType   uint32
	Notes       string
}

// NetworkEventRecord represents a network event
type NetworkEventRecord struct {
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
	Protocol    string // TCP, UDP, etc.
	Severity    EventSeverity
	Status      EventStatus
	Notes       string
}

// SecurityEventRecord represents critical security events (ptrace, module loads, etc.)
type SecurityEventRecord struct {
	ID          int64
	EventTime   int64
	EventType   uint32
	EventName   string // Human-readable event name
	PID         uint32
	UID         uint32
	ProcessName string
	TargetPID   uint32 // For ptrace events
	TargetPath  string // For module/file events
	Details     string // JSON encoded event-specific details
	Severity    EventSeverity
	Status      EventStatus
	YaraMatches []YaraMatchRecord
	ActionTaken string // What action was taken (logged, quarantined, blocked, etc.)
	Notes       string
}

// YaraMatchRecord represents a single YARA rule match
type YaraMatchRecord struct {
	Rule      string   `json:"rule"`
	Namespace string   `json:"namespace"`
	Tags      []string `json:"tags"`
	Strings   []string `json:"strings,omitempty"`
}

// MemoryEventRecord represents memory-related security events
type MemoryEventRecord struct {
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
}

// This is a database handler which is used for controlling the models.
type DBHandler struct {
	AppConfig    utilities.Config
	DB           *sql.DB
	Logger       *zerolog.Logger
	InitRequired bool
	DBPath       string
}

// Creates a new DB and makes it ready for future use.
func (db *DBHandler) initializeDB() {
	if err := db.refreshDBConnection(); err != nil {
		db.Logger.Fatal().Err(err).Msg("cannot continue")
	}

	// Setup local tables
	createTableSQL := `
	-- File scan results table
	CREATE TABLE IF NOT EXISTS file_scan_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_time INTEGER NOT NULL,
		file_path TEXT NOT NULL,
		file_size INTEGER,
		file_hash TEXT,
		yara_matches TEXT, -- JSON array of matches
		severity TEXT NOT NULL DEFAULT 'LOW',
		status TEXT NOT NULL DEFAULT 'NEW',
		event_type INTEGER,
		trigger_pid INTEGER,
		trigger_uid INTEGER,
		trigger_comm TEXT,
		notes TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Process scan results table
	CREATE TABLE IF NOT EXISTS process_scan_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_time INTEGER NOT NULL,
		pid INTEGER NOT NULL,
		ppid INTEGER,
		uid INTEGER NOT NULL,
		gid INTEGER,
		euid INTEGER,
		egid INTEGER,
		process_name TEXT NOT NULL,
		exe_path TEXT,
		cmdline TEXT,
		cwd TEXT,
		yara_matches TEXT, -- JSON array of matches
		severity TEXT NOT NULL DEFAULT 'LOW',
		status TEXT NOT NULL DEFAULT 'NEW',
		event_type INTEGER,
		notes TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Network events table
	CREATE TABLE IF NOT EXISTS network_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_time INTEGER NOT NULL,
		event_type INTEGER NOT NULL,
		pid INTEGER NOT NULL,
		uid INTEGER NOT NULL,
		process_name TEXT NOT NULL,
		src_addr TEXT,
		dst_addr TEXT,
		src_port INTEGER,
		dst_port INTEGER,
		protocol TEXT,
		severity TEXT NOT NULL DEFAULT 'LOW',
		status TEXT NOT NULL DEFAULT 'NEW',
		notes TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Security events table (ptrace, module loads, privilege escalation, etc.)
	CREATE TABLE IF NOT EXISTS security_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_time INTEGER NOT NULL,
		event_type INTEGER NOT NULL,
		event_name TEXT NOT NULL,
		pid INTEGER NOT NULL,
		uid INTEGER NOT NULL,
		process_name TEXT NOT NULL,
		target_pid INTEGER,
		target_path TEXT,
		details TEXT, -- JSON encoded event-specific data
		severity TEXT NOT NULL DEFAULT 'MEDIUM',
		status TEXT NOT NULL DEFAULT 'NEW',
		yara_matches TEXT, -- JSON array of matches
		action_taken TEXT,
		notes TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Memory events table (mmap, mprotect, memfd_create)
	CREATE TABLE IF NOT EXISTS memory_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_time INTEGER NOT NULL,
		event_type INTEGER NOT NULL,
		pid INTEGER NOT NULL,
		uid INTEGER NOT NULL,
		process_name TEXT NOT NULL,
		address INTEGER,
		length INTEGER,
		protection INTEGER,
		flags INTEGER,
		file_path TEXT,
		severity TEXT NOT NULL DEFAULT 'MEDIUM',
		status TEXT NOT NULL DEFAULT 'NEW',
		notes TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Event statistics table
	CREATE TABLE IF NOT EXISTS event_statistics (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		date TEXT NOT NULL, -- YYYY-MM-DD format
		event_type INTEGER NOT NULL,
		event_name TEXT NOT NULL,
		total_count INTEGER DEFAULT 0,
		malicious_count INTEGER DEFAULT 0,
		clean_count INTEGER DEFAULT 0,
		UNIQUE(date, event_type)
	);

	-- Quarantine table
	CREATE TABLE IF NOT EXISTS quarantined_files (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		original_path TEXT NOT NULL,
		quarantine_path TEXT NOT NULL,
		file_hash TEXT NOT NULL,
		file_size INTEGER,
		quarantine_time INTEGER NOT NULL,
		related_scan_id INTEGER,
		severity TEXT NOT NULL,
		reason TEXT NOT NULL,
		restored BOOLEAN DEFAULT 0,
		restored_time INTEGER,
		notes TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Indexes for file_scan_results
	CREATE INDEX IF NOT EXISTS idx_file_scan_time ON file_scan_results(scan_time);
	CREATE INDEX IF NOT EXISTS idx_file_path ON file_scan_results(file_path);
	CREATE INDEX IF NOT EXISTS idx_file_severity ON file_scan_results(severity);
	CREATE INDEX IF NOT EXISTS idx_file_status ON file_scan_results(status);
	CREATE INDEX IF NOT EXISTS idx_file_hash ON file_scan_results(file_hash);
	CREATE INDEX IF NOT EXISTS idx_file_event_type ON file_scan_results(event_type);

	-- Indexes for process_scan_results
	CREATE INDEX IF NOT EXISTS idx_process_scan_time ON process_scan_results(scan_time);
	CREATE INDEX IF NOT EXISTS idx_process_pid ON process_scan_results(pid);
	CREATE INDEX IF NOT EXISTS idx_process_severity ON process_scan_results(severity);
	CREATE INDEX IF NOT EXISTS idx_process_status ON process_scan_results(status);
	CREATE INDEX IF NOT EXISTS idx_process_name ON process_scan_results(process_name);

	-- Indexes for network_events
	CREATE INDEX IF NOT EXISTS idx_network_event_time ON network_events(event_time);
	CREATE INDEX IF NOT EXISTS idx_network_pid ON network_events(pid);
	CREATE INDEX IF NOT EXISTS idx_network_dst_port ON network_events(dst_port);
	CREATE INDEX IF NOT EXISTS idx_network_severity ON network_events(severity);

	-- Indexes for security_events
	CREATE INDEX IF NOT EXISTS idx_security_event_time ON security_events(event_time);
	CREATE INDEX IF NOT EXISTS idx_security_event_type ON security_events(event_type);
	CREATE INDEX IF NOT EXISTS idx_security_pid ON security_events(pid);
	CREATE INDEX IF NOT EXISTS idx_security_severity ON security_events(severity);
	CREATE INDEX IF NOT EXISTS idx_security_status ON security_events(status);

	-- Indexes for memory_events
	CREATE INDEX IF NOT EXISTS idx_memory_event_time ON memory_events(event_time);
	CREATE INDEX IF NOT EXISTS idx_memory_pid ON memory_events(pid);
	CREATE INDEX IF NOT EXISTS idx_memory_severity ON memory_events(severity);

	-- Indexes for quarantine
	CREATE INDEX IF NOT EXISTS idx_quarantine_time ON quarantined_files(quarantine_time);
	CREATE INDEX IF NOT EXISTS idx_quarantine_hash ON quarantined_files(file_hash);
	CREATE INDEX IF NOT EXISTS idx_quarantine_severity ON quarantined_files(severity);
	`
	_, err := db.DB.Exec(createTableSQL)
	if err != nil {
		db.Logger.Fatal().Err(err).Msg("failed to create tables in database")
	}

	db.InitRequired = false
}

// Refreshes your DB connection.
func (db *DBHandler) refreshDBConnection() error {
	var err error
	db.DB, err = sql.Open("sqlite3", db.DBPath)
	if err != nil {
		db.Logger.Fatal().Err(err).Msg("failed to open database")
		return err
	}
	return nil
}

func NewDBHandler(config utilities.Config, logger *zerolog.Logger) *DBHandler {
	databasePath := filepath.Join(config.GenericSettings.DbDirectory, config.GenericSettings.DbFilename)

	// Check if database file exists
	var dbInitRequired = false
	if _, err := os.Stat(databasePath); err == nil {
		dbInitRequired = true
		logger.Info().Str("db_path", databasePath).Msg("database already exists")
	} else {
		logger.Warn().Str("db_path", databasePath).Msg("database doesnt exist and will be initialized on first run")
	}

	// Open or create the database.
	db, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to open database")
	}
	// defer db.Close()

	// Set pragmas for better performance
	_, _ = db.Exec("PRAGMA journal_mode=WAL")
	_, _ = db.Exec("PRAGMA synchronous=NORMAL")
	_, _ = db.Exec("PRAGMA cache_size=10000")
	_, _ = db.Exec("PRAGMA temp_store=MEMORY")

	return &DBHandler{
		DB:           db,
		Logger:       logger,
		AppConfig:    config,
		InitRequired: dbInitRequired,
		DBPath:       databasePath,
	}
}

// Initializes your DB and loads a connection into DB Handler.
func (db *DBHandler) SetupDatabase() {
	if db.InitRequired {
		db.initializeDB()
	}

	// Check DB connection
	if err := db.DB.Ping(); err != nil {
		db.Logger.Fatal().Err(err).Msg("failed to ping database")
	}

	// Load connection
	if err := db.refreshDBConnection(); err != nil {
		db.Logger.Fatal().Err(err).Msg("failed to load database connection")
	}

	db.Logger.Info().Msg("database is ready")
}

// Close closes the database connection
func (db *DBHandler) Close() error {
	if db.DB != nil {
		return db.DB.Close()
	}
	return nil
}

// InsertFileScanResult inserts a file scan result into the database
func (db *DBHandler) InsertFileScanResult(result *FileScanResult) error {
	yaraJSON, err := json.Marshal(result.YaraMatches)
	if err != nil {
		return fmt.Errorf("marshal yara matches: %w", err)
	}

	query := `
		INSERT INTO file_scan_results 
		(scan_time, file_path, file_size, file_hash, yara_matches, severity, status, 
		 event_type, trigger_pid, trigger_uid, trigger_comm, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = db.DB.Exec(query,
		result.ScanTime,
		result.FilePath,
		result.FileSize,
		result.FileHash,
		string(yaraJSON),
		result.Severity,
		result.Status,
		result.EventType,
		result.TriggerPID,
		result.TriggerUID,
		result.TriggerComm,
		result.Notes,
	)

	return err
}

// InsertProcessScanResult inserts a process scan result into the database
func (db *DBHandler) InsertProcessScanResult(result *ProcessScanResult) error {
	yaraJSON, err := json.Marshal(result.YaraMatches)
	if err != nil {
		return fmt.Errorf("marshal yara matches: %w", err)
	}

	query := `
		INSERT INTO process_scan_results
		(scan_time, pid, ppid, uid, gid, euid, egid, process_name, exe_path,
		 cmdline, cwd, yara_matches, severity, status, event_type, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = db.DB.Exec(query,
		result.ScanTime,
		result.PID,
		result.PPID,
		result.UID,
		result.GID,
		result.EUID,
		result.EGID,
		result.ProcessName,
		result.ExePath,
		result.CmdLine,
		result.CWD,
		string(yaraJSON),
		result.Severity,
		result.Status,
		result.EventType,
		result.Notes,
	)

	return err
}

// InsertNetworkEvent inserts a network event into the database
func (db *DBHandler) InsertNetworkEvent(event *NetworkEventRecord) error {
	query := `
		INSERT INTO network_events
		(event_time, event_type, pid, uid, process_name, src_addr, dst_addr,
		 src_port, dst_port, protocol, severity, status, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := db.DB.Exec(query,
		event.EventTime,
		event.EventType,
		event.PID,
		event.UID,
		event.ProcessName,
		event.SrcAddr,
		event.DstAddr,
		event.SrcPort,
		event.DstPort,
		event.Protocol,
		event.Severity,
		event.Status,
		event.Notes,
	)

	return err
}

// InsertSecurityEvent inserts a security event into the database
func (db *DBHandler) InsertSecurityEvent(event *SecurityEventRecord) error {
	yaraJSON, err := json.Marshal(event.YaraMatches)
	if err != nil {
		return fmt.Errorf("marshal yara matches: %w", err)
	}

	query := `
		INSERT INTO security_events
		(event_time, event_type, event_name, pid, uid, process_name, target_pid,
		 target_path, details, severity, status, yara_matches, action_taken, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = db.DB.Exec(query,
		event.EventTime,
		event.EventType,
		event.EventName,
		event.PID,
		event.UID,
		event.ProcessName,
		event.TargetPID,
		event.TargetPath,
		event.Details,
		event.Severity,
		event.Status,
		string(yaraJSON),
		event.ActionTaken,
		event.Notes,
	)

	return err
}

// InsertMemoryEvent inserts a memory event into the database
func (db *DBHandler) InsertMemoryEvent(event *MemoryEventRecord) error {
	query := `
		INSERT INTO memory_events
		(event_time, event_type, pid, uid, process_name, address, length,
		 protection, flags, file_path, severity, status, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := db.DB.Exec(query,
		event.EventTime,
		event.EventType,
		event.PID,
		event.UID,
		event.ProcessName,
		event.Address,
		event.Length,
		event.Protection,
		event.Flags,
		event.FilePath,
		event.Severity,
		event.Status,
		event.Notes,
	)

	return err
}

// BatchInsertFileScanResults inserts multiple file scan results efficiently
func (db *DBHandler) BatchInsertFileScanResults(results []FileScanResult) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := db.DB.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO file_scan_results
		(scan_time, file_path, file_size, file_hash, yara_matches, severity, status,
		 event_type, trigger_pid, trigger_uid, trigger_comm, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, result := range results {
		yaraJSON, err := json.Marshal(result.YaraMatches)
		if err != nil {
			db.Logger.Error().Err(err).Str("file", result.FilePath).Msg("failed to marshal yara matches")
			continue
		}

		_, err = stmt.Exec(
			result.ScanTime,
			result.FilePath,
			result.FileSize,
			result.FileHash,
			string(yaraJSON),
			result.Severity,
			result.Status,
			result.EventType,
			result.TriggerPID,
			result.TriggerUID,
			result.TriggerComm,
			result.Notes,
		)
		if err != nil {
			db.Logger.Error().Err(err).Str("file", result.FilePath).Msg("failed to insert result")
			continue
		}
	}

	return tx.Commit()
}

// UpdateEventStatus updates the status of any event type
func (db *DBHandler) UpdateEventStatus(table string, id int64, status EventStatus, notes string) error {
	query := fmt.Sprintf(`
		UPDATE %s
		SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, table)

	_, err := db.DB.Exec(query, status, notes, id)
	return err
}

// GetMaliciousEvents retrieves all malicious events within a time range
func (db *DBHandler) GetMaliciousEvents(startTime, endTime int64) ([]interface{}, error) {
	var events []interface{}

	// Query file scans
	fileQuery := `
		SELECT id, scan_time, file_path, severity, status, yara_matches
		FROM file_scan_results
		WHERE scan_time BETWEEN ? AND ?
		AND severity IN ('HIGH', 'CRITICAL')
		ORDER BY scan_time DESC
	`

	rows, err := db.DB.Query(fileQuery, startTime, endTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var result FileScanResult
		var yaraJSON string
		err := rows.Scan(&result.ID, &result.ScanTime, &result.FilePath,
			&result.Severity, &result.Status, &yaraJSON)
		if err != nil {
			continue
		}
		json.Unmarshal([]byte(yaraJSON), &result.YaraMatches)
		events = append(events, result)
	}

	return events, nil
}

// ConvertYaraMatchRulesToRecords converts go-yara MatchRules to YaraMatchRecord
func ConvertYaraMatchRulesToRecords(matches yara.MatchRules) []YaraMatchRecord {
	records := make([]YaraMatchRecord, 0, len(matches))
	for _, match := range matches {
		strings := make([]string, 0, len(match.Strings))
		for _, str := range match.Strings {
			strings = append(strings, string(str.Data))
		}

		records = append(records, YaraMatchRecord{
			Rule:      match.Rule,
			Namespace: match.Namespace,
			Tags:      match.Tags,
			Strings:   strings,
		})
	}
	return records
}
