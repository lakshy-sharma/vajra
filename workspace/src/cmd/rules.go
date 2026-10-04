// cmd/rules.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"vajra/internal/jobs"
	"vajra/internal/utilities"
)

// rulesCmd is the parent command for rule management operations.
var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage YARA rules",
	Long:  "Commands for managing the YARA ruleset used by Vajra.",
}

// rulesUpdateCmd triggers an immediate rule sync cycle.
var rulesUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check for and download updated YARA rules",
	Long: `Checks the remote hash against the local rules archive.
If the hashes differ, downloads the new ruleset, verifies it,
archives the current rules, and restarts the agent via systemd.

Safe to run while the agent is running — the agent will be
restarted automatically after a successful update.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, _ := cmd.Flags().GetString("config")
		cfg, err := utilities.LoadConfig(configPath)
		if err != nil {
			return fmt.Errorf("rules update: load config: %w", err)
		}

		logger := utilities.GetLogger(cfg)
		syncer := jobs.NewRuleSyncer(logger, cfg.RulesSettings)

		fmt.Println("Checking for rule updates...")
		if err := syncer.RunOnce(); err != nil {
			fmt.Fprintf(os.Stderr, "Rule update failed: %v\n", err)
			return err
		}

		fmt.Println("Rule sync complete.")
		return nil
	},
}

// rulesStatusCmd shows the current rules state.
var rulesStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current rules status",
	Long:  "Displays the current rules file path, hash, and archive count.",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath, _ := cmd.Flags().GetString("config")
		cfg, err := utilities.LoadConfig(configPath)
		if err != nil {
			return fmt.Errorf("rules status: load config: %w", err)
		}

		// Hash the current rules file.
		logger := utilities.GetLogger(cfg)
		syncer := jobs.NewRuleSyncer(logger, cfg.RulesSettings)

		hash, err := syncer.LocalHash()
		if err != nil {
			fmt.Printf("Rules file : %s\n", cfg.RulesSettings.RulesFilepath)
			fmt.Printf("Hash       : unavailable (%v)\n", err)
		} else {
			fmt.Printf("Rules file : %s\n", cfg.RulesSettings.RulesFilepath)
			fmt.Printf("Hash       : %s\n", hash)
		}

		// Count archives.
		entries, err := os.ReadDir(cfg.RulesSettings.RulesArchiveDir)
		if err != nil {
			fmt.Printf("Archives   : unavailable (%v)\n", err)
		} else {
			count := 0
			for _, e := range entries {
				if !e.IsDir() {
					count++
				}
			}
			fmt.Printf("Archives   : %d / %d\n", count, cfg.RulesSettings.RulesArchiveCount)
			fmt.Printf("Archive dir: %s\n", cfg.RulesSettings.RulesArchiveDir)
		}

		return nil
	},
}

func init() {
	rulesCmd.AddCommand(rulesUpdateCmd)
	rulesCmd.AddCommand(rulesStatusCmd)
	rootCmd.AddCommand(rulesCmd)
}
