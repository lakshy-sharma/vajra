// cmd/secrets.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
	"vajra/internal/db"
	"vajra/internal/db/queries"
	"vajra/internal/detect"
	"vajra/internal/utilities"
	"vajra/shared/models"
)

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage secrets scanner findings and ignore list",
}

var secretsIgnoreCmd = &cobra.Command{
	Use:   "ignore <detection_id>",
	Short: "Mark a secrets detection as IGNORED",
	Long: `Sets the status of a secrets detection to IGNORED.
Ignored detections are excluded from the ignore file when
'vajra secrets export-ignore' is run.`,
	Args: cobra.ExactArgs(1),
	RunE: runSecretsIgnore,
}

var secretsExportIgnoreCmd = &cobra.Command{
	Use:   "export-ignore",
	Short: "Export ignored secret fingerprints to the ignore file",
	Long: `Queries all detection_secrets records whose parent detection has
status = IGNORED, then writes their betterleaks fingerprints to
secrets.ignore in the database directory.

The ignore file is read by the secrets scanner on the next daemon
restart or scan cycle start. Existing ignore file is replaced — the
file always reflects the current set of IGNORED detections exactly.`,
	Args: cobra.NoArgs,
	RunE: runSecretsExportIgnore,
}

func init() {
	secretsCmd.AddCommand(secretsIgnoreCmd)
	secretsCmd.AddCommand(secretsExportIgnoreCmd)
	rootCmd.AddCommand(secretsCmd)
}

func runSecretsIgnore(cmd *cobra.Command, args []string) error {
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("secrets ignore: invalid detection_id %q: %w", args[0], err)
	}

	cfg, err := utilities.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("secrets ignore: load config: %w", err)
	}

	dbPath := filepath.Join(cfg.GenericSettings.DBDirectory, cfg.GenericSettings.DBFilename)
	logger := utilities.GetLogger(cfg)
	database, err := db.Open(dbPath, logger)
	if err != nil {
		return fmt.Errorf("secrets ignore: open db: %w", err)
	}
	defer database.Close()

	detQ := queries.NewDetectionQueries(database)
	if err := detQ.UpdateStatus(id, models.StatusIgnored, "marked ignored via CLI"); err != nil {
		return fmt.Errorf("secrets ignore: update status: %w", err)
	}

	fmt.Printf("Detection %d marked as IGNORED.\n", id)
	fmt.Println("Run 'vajra secrets export-ignore' to update the ignore file,")
	fmt.Println("then restart the daemon for it to take effect.")
	return nil
}

func runSecretsExportIgnore(cmd *cobra.Command, args []string) error {
	cfg, err := utilities.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("secrets export-ignore: load config: %w", err)
	}

	dbPath := filepath.Join(cfg.GenericSettings.DBDirectory, cfg.GenericSettings.DBFilename)
	logger := utilities.GetLogger(cfg)
	database, err := db.Open(dbPath, logger)
	if err != nil {
		return fmt.Errorf("secrets export-ignore: open db: %w", err)
	}
	defer database.Close()

	fingerprints, err := queries.NewSecretQueries(database).ListIgnoredFingerprints()
	if err != nil {
		return fmt.Errorf("secrets export-ignore: query fingerprints: %w", err)
	}

	if len(fingerprints) == 0 {
		fmt.Println("No ignored secret detections found. Nothing written.")
		return nil
	}

	ignorePath := filepath.Join(cfg.GenericSettings.DBDirectory, detect.IgnoreFileName)

	// Write atomically: write to a temp file then rename.
	// Prevents the daemon from reading a partially written ignore file.
	tmpPath := ignorePath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("secrets export-ignore: create temp file: %w", err)
	}

	w := bufio.NewWriter(f)
	for _, fp := range fingerprints {
		if _, err := fmt.Fprintln(w, fp); err != nil {
			f.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("secrets export-ignore: write: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("secrets export-ignore: flush: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("secrets export-ignore: close: %w", err)
	}

	if err := os.Rename(tmpPath, ignorePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("secrets export-ignore: rename: %w", err)
	}

	fmt.Printf("Wrote %d fingerprint(s) to %s\n", len(fingerprints), ignorePath)
	fmt.Println("Restart the daemon for the ignore list to take effect.")
	return nil
}
