package internal

import (
	"database/sql"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

var (
	DB *sql.DB
)

// Check if database exists on the system and create one if it does not.
// If DB exists then establish a connection.
func setupDB() {
	databasePath := filepath.Join(GlobalConfig.GenericSettings.DbDirectory, GlobalConfig.GenericSettings.DbFilename)

	// Check if database file exists
	dbExists := false
	if _, err := os.Stat(databasePath); err == nil {
		dbExists = true
		logger.Info().Msg("database already exists")
	}

	// Open or create the database.
	db, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to open database")
	}
	defer db.Close()

	// Create tables if DB does not exist.
	if !dbExists {
		createTables()
	}

	// Check DB connection
	if err := db.Ping(); err != nil {
		logger.Fatal().Err(err).Msg("failed to ping database")
	}

	// Load connection
	if err := getDBConnection(); err != nil {
		logger.Fatal().Err(err).Msg("failed to load database connection")
	}

	logger.Info().Str("db_path", databasePath).Msg("database is ready")
}

func createTables() {
	if err := getDBConnection(); err != nil {
		logger.Fatal().Err(err).Msg("cannot continue")
	}

	// Setup local tables
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS file_scan_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		lastscan_time INTEGER NOT NULL,
		filepath TEXT NOT NULL,
		yara_results BLOB
	);
	CREATE TABLE IF NOT EXISTS process_scan_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		lastscan_time INTEGER NOT NULL,
		pid INTEGER NOT NULL,
		process_name TEXT NOT NULL,
		cmdline TEXT,
		yara_results TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX idx_file_scan_time ON file_scan_results(lastscan_time);
	CREATE INDEX idx_file_path ON file_scan_results(filepath);
	CREATE INDEX idx_process_scan_time ON process_scan_results(lastscan_time);
	CREATE INDEX idx_process_pid ON process_scan_results(pid);
	`
	_, err := DB.Exec(createTableSQL)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create tables in our database")
	}

}

func getDBConnection() error {
	databasePath := filepath.Join(GlobalConfig.GenericSettings.DbDirectory, GlobalConfig.GenericSettings.DbFilename)
	var err error
	DB, err = sql.Open("sqlite3", databasePath)
	if err != nil {
		logger.Error().Err(err).Msg("failed to open database")
		return err
	}
	return nil
}
