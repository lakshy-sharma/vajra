// internal/db/open.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package db

import (
	"context"
	"fmt"

	shareddb "vajra/shared/db"
)

// Open opens the daemon database and runs schema migrations.
func Open(path string) (*shareddb.DB, error) {
	db, err := shareddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("db.Open: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("db.Open: migrate: %w", err)
	}
	return db, nil
}

func migrate(db shareddb.DBConn) error {
	ctx := context.Background()
	stmts := []string{
		// ── detections ────────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS detections (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			machine_id      TEXT    NOT NULL DEFAULT '',
			detection_time  INTEGER NOT NULL,
			source          TEXT    NOT NULL,
			severity        TEXT    NOT NULL DEFAULT 'LOW',
			status          TEXT    NOT NULL DEFAULT 'NEW',
			pid             INTEGER NOT NULL DEFAULT 0,
			ppid            INTEGER NOT NULL DEFAULT 0,
			uid             INTEGER NOT NULL DEFAULT 0,
			gid             INTEGER NOT NULL DEFAULT 0,
			euid            INTEGER NOT NULL DEFAULT 0,
			egid            INTEGER NOT NULL DEFAULT 0,
			process_name    TEXT    NOT NULL DEFAULT '',
			exe_path        TEXT    NOT NULL DEFAULT '',
			cmd_line        TEXT    NOT NULL DEFAULT '',
			cwd             TEXT    NOT NULL DEFAULT '',
			target_path     TEXT    NOT NULL DEFAULT '',
			rule_id         TEXT    NOT NULL DEFAULT '',
			mitre_technique TEXT    NOT NULL DEFAULT '',
			dedup_count     INTEGER NOT NULL DEFAULT 0,
			notes           TEXT    NOT NULL DEFAULT '',
			created_at      INTEGER NOT NULL DEFAULT 0,
			updated_at      INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_det_machine_id     ON detections(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_det_detection_time ON detections(detection_time)`,
		`CREATE INDEX IF NOT EXISTS idx_det_source         ON detections(source)`,
		`CREATE INDEX IF NOT EXISTS idx_det_severity       ON detections(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_det_status         ON detections(status)`,
		`CREATE INDEX IF NOT EXISTS idx_det_target_path    ON detections(target_path)`,
		`CREATE INDEX IF NOT EXISTS idx_det_rule_id        ON detections(rule_id)`,
		`CREATE INDEX IF NOT EXISTS idx_det_pid            ON detections(pid)`,

		// ── detection_artifacts ───────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS detection_artifacts (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			detection_id INTEGER NOT NULL REFERENCES detections(id),
			file_hash    TEXT    NOT NULL DEFAULT '',
			file_size    INTEGER NOT NULL DEFAULT 0,
			yara_matches TEXT    NOT NULL DEFAULT '[]'
		)`,
		`CREATE INDEX IF NOT EXISTS idx_da_detection_id ON detection_artifacts(detection_id)`,
		`CREATE INDEX IF NOT EXISTS idx_da_file_hash    ON detection_artifacts(file_hash)`,

		// ── detection_network ─────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS detection_network (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			detection_id INTEGER NOT NULL REFERENCES detections(id),
			remote_addr  TEXT    NOT NULL DEFAULT '',
			remote_port  INTEGER NOT NULL DEFAULT 0,
			protocol     TEXT    NOT NULL DEFAULT '',
			socket_inode INTEGER NOT NULL DEFAULT 0,
			old_fd       INTEGER NOT NULL DEFAULT 0,
			new_fd       INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dn_detection_id ON detection_network(detection_id)`,

		// ── detection_secrets ─────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS detection_secrets (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			detection_id  INTEGER NOT NULL REFERENCES detections(id),
			rule_id       TEXT    NOT NULL,
			secret_hash   TEXT    NOT NULL,
			fingerprint   TEXT    NOT NULL DEFAULT '',
			start_line    INTEGER NOT NULL DEFAULT 0,
			end_line      INTEGER NOT NULL DEFAULT 0,
			match_context TEXT    NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ds_detection_id ON detection_secrets(detection_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ds_secret_hash  ON detection_secrets(secret_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_ds_rule_id      ON detection_secrets(rule_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ds_fingerprint  ON detection_secrets(fingerprint)`,

		// ── detection_extensions ──────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS detection_extensions (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			detection_id INTEGER NOT NULL REFERENCES detections(id),
			key          TEXT    NOT NULL,
			value        TEXT    NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_de_detection_id ON detection_extensions(detection_id)`,
		`CREATE INDEX IF NOT EXISTS idx_de_key          ON detection_extensions(key)`,
		`CREATE INDEX IF NOT EXISTS idx_de_key_value    ON detection_extensions(key, value)`,

		// ── evidence_snapshots ────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS evidence_snapshots (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			detection_id INTEGER NOT NULL REFERENCES detections(id),
			captured_at  INTEGER NOT NULL,
			open_fds     TEXT    NOT NULL DEFAULT '[]',
			maps         TEXT    NOT NULL DEFAULT '[]',
			environ      TEXT    NOT NULL DEFAULT '{}',
			status       TEXT    NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_es_detection_id ON evidence_snapshots(detection_id)`,

		// ── audit_log ─────────────────────────────────────────────────────────
		// Append-only: no UPDATE path exists by design.
		`CREATE TABLE IF NOT EXISTS audit_log (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			machine_id      TEXT    NOT NULL DEFAULT '',
			logged_at       INTEGER NOT NULL,
			component       TEXT    NOT NULL,
			event_type      TEXT    NOT NULL,
			status          TEXT    NOT NULL DEFAULT 'ok',
			details         TEXT    NOT NULL DEFAULT '',
			duration_ms     INTEGER NOT NULL DEFAULT 0,
			items_processed INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_al_machine_id ON audit_log(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_al_logged_at  ON audit_log(logged_at)`,
		`CREATE INDEX IF NOT EXISTS idx_al_component  ON audit_log(component)`,
		`CREATE INDEX IF NOT EXISTS idx_al_event_type ON audit_log(event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_al_status     ON audit_log(status)`,

		// ── network_events ────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS network_events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			machine_id   TEXT    NOT NULL DEFAULT '',
			event_time   INTEGER NOT NULL,
			event_type   INTEGER NOT NULL,
			pid          INTEGER NOT NULL,
			uid          INTEGER NOT NULL,
			process_name TEXT    NOT NULL DEFAULT '',
			src_addr     TEXT    NOT NULL DEFAULT '',
			dst_addr     TEXT    NOT NULL DEFAULT '',
			src_port     INTEGER NOT NULL DEFAULT 0,
			dst_port     INTEGER NOT NULL DEFAULT 0,
			protocol     TEXT    NOT NULL DEFAULT '',
			severity     TEXT    NOT NULL DEFAULT 'LOW',
			status       TEXT    NOT NULL DEFAULT 'NEW',
			notes        TEXT    NOT NULL DEFAULT '',
			created_at   INTEGER NOT NULL DEFAULT 0,
			updated_at   INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ne_machine_id ON network_events(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ne_event_time ON network_events(event_time)`,
		`CREATE INDEX IF NOT EXISTS idx_ne_pid        ON network_events(pid)`,
		`CREATE INDEX IF NOT EXISTS idx_ne_dst_port   ON network_events(dst_port)`,
		`CREATE INDEX IF NOT EXISTS idx_ne_severity   ON network_events(severity)`,

		// ── security_events ───────────────────────────────────────────────────
		// yara_matches removed — EventSink never runs YARA; see DetectionArtifact.
		`CREATE TABLE IF NOT EXISTS security_events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			machine_id   TEXT    NOT NULL DEFAULT '',
			event_time   INTEGER NOT NULL,
			event_type   INTEGER NOT NULL,
			event_name   TEXT    NOT NULL,
			pid          INTEGER NOT NULL,
			uid          INTEGER NOT NULL,
			process_name TEXT    NOT NULL DEFAULT '',
			target_pid   INTEGER NOT NULL DEFAULT 0,
			target_path  TEXT    NOT NULL DEFAULT '',
			details      TEXT    NOT NULL DEFAULT '',
			severity     TEXT    NOT NULL DEFAULT 'MEDIUM',
			status       TEXT    NOT NULL DEFAULT 'NEW',
			action_taken TEXT    NOT NULL DEFAULT '',
			notes        TEXT    NOT NULL DEFAULT '',
			created_at   INTEGER NOT NULL DEFAULT 0,
			updated_at   INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_se_machine_id ON security_events(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_se_event_time ON security_events(event_time)`,
		`CREATE INDEX IF NOT EXISTS idx_se_event_type ON security_events(event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_se_pid        ON security_events(pid)`,
		`CREATE INDEX IF NOT EXISTS idx_se_severity   ON security_events(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_se_status     ON security_events(status)`,

		// ── memory_events ─────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS memory_events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			machine_id   TEXT    NOT NULL DEFAULT '',
			event_time   INTEGER NOT NULL,
			event_type   INTEGER NOT NULL,
			pid          INTEGER NOT NULL,
			uid          INTEGER NOT NULL,
			process_name TEXT    NOT NULL DEFAULT '',
			address      INTEGER NOT NULL DEFAULT 0,
			length       INTEGER NOT NULL DEFAULT 0,
			protection   INTEGER NOT NULL DEFAULT 0,
			flags        INTEGER NOT NULL DEFAULT 0,
			file_path    TEXT    NOT NULL DEFAULT '',
			severity     TEXT    NOT NULL DEFAULT 'MEDIUM',
			status       TEXT    NOT NULL DEFAULT 'NEW',
			notes        TEXT    NOT NULL DEFAULT '',
			created_at   INTEGER NOT NULL DEFAULT 0,
			updated_at   INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_me_machine_id ON memory_events(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_me_event_time ON memory_events(event_time)`,
		`CREATE INDEX IF NOT EXISTS idx_me_pid        ON memory_events(pid)`,
		`CREATE INDEX IF NOT EXISTS idx_me_severity   ON memory_events(severity)`,

		// ── autoruns ──────────────────────────────────────────────────────────
		// md5/sha1 removed — sha256 is the only hash we store and verify.
		`CREATE TABLE IF NOT EXISTS autoruns (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			machine_id  TEXT    NOT NULL DEFAULT '',
			category    TEXT    NOT NULL,
			location    TEXT    NOT NULL,
			image_path  TEXT    NOT NULL DEFAULT '',
			image_name  TEXT    NOT NULL DEFAULT '',
			arguments   TEXT    NOT NULL DEFAULT '',
			sha256      TEXT    NOT NULL DEFAULT '',
			is_active   INTEGER NOT NULL DEFAULT 1,
			first_seen  INTEGER NOT NULL,
			last_seen   INTEGER NOT NULL,
			created_at  INTEGER NOT NULL DEFAULT 0,
			updated_at  INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ar_machine_id ON autoruns(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ar_category   ON autoruns(category)`,
		`CREATE INDEX IF NOT EXISTS idx_ar_location   ON autoruns(location)`,
		`CREATE INDEX IF NOT EXISTS idx_ar_image_path ON autoruns(image_path)`,
		`CREATE INDEX IF NOT EXISTS idx_ar_sha256     ON autoruns(sha256)`,
		`CREATE INDEX IF NOT EXISTS idx_ar_is_active  ON autoruns(is_active)`,
		`CREATE INDEX IF NOT EXISTS idx_ar_last_seen  ON autoruns(last_seen)`,

		// ── quarantined_files ─────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS quarantined_files (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			original_path   TEXT    NOT NULL,
			quarantine_path TEXT    NOT NULL,
			file_hash       TEXT    NOT NULL,
			file_size       INTEGER NOT NULL DEFAULT 0,
			quarantine_time INTEGER NOT NULL,
			related_id      INTEGER REFERENCES detections(id),
			severity        TEXT    NOT NULL,
			reason          TEXT    NOT NULL,
			restored        INTEGER NOT NULL DEFAULT 0,
			restored_time   INTEGER NOT NULL DEFAULT 0,
			notes           TEXT    NOT NULL DEFAULT '',
			created_at      INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_qf_quarantine_time ON quarantined_files(quarantine_time)`,
		`CREATE INDEX IF NOT EXISTS idx_qf_file_hash       ON quarantined_files(file_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_qf_severity        ON quarantined_files(severity)`,

		// ── event_statistics ──────────────────────────────────────────────────
		// date is the Unix epoch of the UTC day start, not a formatted string.
		`CREATE TABLE IF NOT EXISTS event_statistics (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			date            INTEGER NOT NULL,
			event_type      INTEGER NOT NULL,
			event_name      TEXT    NOT NULL,
			total_count     INTEGER NOT NULL DEFAULT 0,
			malicious_count INTEGER NOT NULL DEFAULT 0,
			clean_count     INTEGER NOT NULL DEFAULT 0,
			UNIQUE(date, event_type)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_es_date       ON event_statistics(date)`,
		`CREATE INDEX IF NOT EXISTS idx_es_event_type ON event_statistics(event_type)`,

		// ── sync_state ────────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS sync_state (
			table_name     TEXT    PRIMARY KEY,
			last_synced_id INTEGER NOT NULL DEFAULT 0,
			last_synced_at INTEGER NOT NULL DEFAULT 0,
			synced_rows    INTEGER NOT NULL DEFAULT 0
		)`,

		// ── process_tree ──────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS process_tree (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			machine_id TEXT    NOT NULL DEFAULT '',
			pid        INTEGER NOT NULL,
			ppid       INTEGER NOT NULL,
			comm       TEXT    NOT NULL DEFAULT '',
			exe_path   TEXT    NOT NULL DEFAULT '',
			cmdline    TEXT    NOT NULL DEFAULT '',
			event_time INTEGER NOT NULL,
			created_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pt_machine_id       ON process_tree(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_pt_pid              ON process_tree(pid)`,
		`CREATE INDEX IF NOT EXISTS idx_pt_ppid             ON process_tree(ppid)`,
		`CREATE INDEX IF NOT EXISTS idx_pt_event_time       ON process_tree(event_time)`,
		`CREATE INDEX IF NOT EXISTS idx_pt_machine_ppid_pid ON process_tree(machine_id, ppid, pid)`,

		// ── app_config ────────────────────────────────────────────────────────
		// Single-row (CHECK id=1). DBDirectory and DBFilename intentionally
		// absent — they must always come from YAML (chicken-and-egg).
		`CREATE TABLE IF NOT EXISTS app_config (
			id             INTEGER PRIMARY KEY CHECK (id = 1),
			config_json    TEXT    NOT NULL,
			schema_version INTEGER NOT NULL DEFAULT 0,
			yaml_path      TEXT    NOT NULL,
			updated_at     INTEGER NOT NULL DEFAULT 0
		)`,
	}

	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: %.120s: %w", stmt, err)
		}
	}

	// Compact WAL after migration to reclaim disk space on fresh installs.
	_, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}
