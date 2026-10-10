// cmd/configwrite.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License
//
// This subcommand is the polkit-authorised target for privileged config writes.
// The UI calls:
//
//	pkexec /opt/vajra/vajra config-write --config /etc/vajra/config.yaml
//
// and pipes the new YAML on stdin. polkit presents the native auth dialog;
// if the user authenticates, pkexec runs this as root, which:
//   - reads the existing YAML to preserve DB path fields (chicken-and-egg)
//   - merges the incoming YAML over it (DBDirectory/DBFilename are never overwritten)
//   - writes the merged config back to the same path
//
// Security notes:
//   - DBDirectory and DBFilename are always kept from the on-disk YAML; the
//     incoming document cannot change them, preventing path-traversal attacks.
//   - stdin is the only channel; no Unix socket, no env-var injection.
//   - The process is launched by pkexec, so it runs as root only after the
//     logged-in active session user authenticates via polkit.

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	sharedconfig "vajra/shared/config"
)

var configWriteCmd = &cobra.Command{
	Use:    "config-write",
	Short:  "Write config (called by UI via pkexec — not for direct use)",
	Hidden: true, // hide from `vajra help`; this is an internal plumbing command
	Long: `Reads a JSON-encoded Config from stdin and writes it back to --config as YAML.

DBDirectory and DBFilename are always preserved from the existing on-disk file
regardless of what the incoming JSON contains. This command is intended to be
invoked exclusively by the Vajra desktop UI through pkexec.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if configPath == "" {
			return fmt.Errorf("config-write: --config path is required")
		}

		// 1. Read the existing on-disk YAML so we can preserve DB path fields.
		existing, err := sharedconfig.LoadConfig(configPath)
		if err != nil {
			return fmt.Errorf("config-write: load existing config: %w", err)
		}
		savedDBDir := existing.GenericSettings.DBDirectory
		savedDBFile := existing.GenericSettings.DBFilename

		// 2. Decode the incoming JSON from stdin into a new Config.
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("config-write: read stdin: %w", err)
		}
		var incoming sharedconfig.Config
		if err := json.Unmarshal(raw, &incoming); err != nil {
			return fmt.Errorf("config-write: parse incoming JSON: %w", err)
		}

		// 3. Enforce the DB path invariant — these are always sourced from
		// the YAML file and must never be overwritten by the UI.
		incoming.GenericSettings.DBDirectory = savedDBDir
		incoming.GenericSettings.DBFilename = savedDBFile

		// 4. Write the merged config back.
		if err := sharedconfig.SaveConfig(incoming, configPath); err != nil {
			return fmt.Errorf("config-write: save: %w", err)
		}

		fmt.Fprintf(os.Stdout, "config-write: wrote %s\n", configPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(configWriteCmd)
}
