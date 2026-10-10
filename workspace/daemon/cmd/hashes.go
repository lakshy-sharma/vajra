// cmd/hashes.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package cmd

import (
	"fmt"
	"os"
	"vajra/internal/job"
	"vajra/internal/utilities"

	"github.com/spf13/cobra"

	sharedconfig "vajra/shared/config"
)

var hashesCmd = &cobra.Command{
	Use:   "hashes",
	Short: "Manage malware hash database",
}

var hashesUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Download MalwareBazaar dataset and rebuild Bloom filter",
	Long: `Downloads the MalwareBazaar full CSV export, extracts SHA256 hashes,
and writes a Bloom filter to the path configured in threat_intel_settings.

Requires malware_bazaar_auth_key to be set in config.
The existing zip is reused if present — delete it to force a fresh download.
The daemon must be restarted for the new filter to take effect.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := sharedconfig.LoadConfig(configPath)
		if err != nil {
			return fmt.Errorf("hashes update: load config: %w", err)
		}

		if cfg.ThreatIntelSettings.MalwareBazaarAuthKey == "" {
			fmt.Fprintln(os.Stderr, "hashes update: malware_bazaar_auth_key not set in config")
			return fmt.Errorf("no auth key configured")
		}

		logger := utilities.GetLogger(&cfg)
		syncer := job.NewHashSyncer(logger, cfg.ThreatIntelSettings)

		fmt.Println("Syncing malware hashes...")
		if err := syncer.RunOnce(); err != nil {
			fmt.Fprintf(os.Stderr, "Hash sync failed: %v\n", err)
			return err
		}

		fmt.Printf("Bloom filter written to %s\n", cfg.ThreatIntelSettings.BloomFilterPath)
		fmt.Println("Restart the daemon for the new filter to take effect.")
		return nil
	},
}

var hashesStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show hash database status",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := sharedconfig.LoadConfig(configPath)
		if err != nil {
			return fmt.Errorf("hashes status: load config: %w", err)
		}

		path := cfg.ThreatIntelSettings.BloomFilterPath
		info, err := os.Stat(path)
		if err != nil {
			fmt.Printf("Bloom filter : %s\n", path)
			fmt.Printf("Status       : not found\n")
			return nil
		}

		fmt.Printf("Bloom filter : %s\n", path)
		fmt.Printf("Size         : %.1f MB\n", float64(info.Size())/1024/1024)
		fmt.Printf("Modified     : %s\n", info.ModTime().Format("2006-01-02 15:04:05"))
		fmt.Printf("Auth key     : %s\n", maskKey(cfg.ThreatIntelSettings.MalwareBazaarAuthKey))
		return nil
	},
}

func init() {
	hashesCmd.AddCommand(hashesUpdateCmd)
	hashesCmd.AddCommand(hashesStatusCmd)
	rootCmd.AddCommand(hashesCmd)
}

// maskKey shows only the first and last 4 characters of the auth key.
func maskKey(key string) string {
	if key == "" {
		return "not configured"
	}
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}
