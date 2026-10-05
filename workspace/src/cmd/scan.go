// cmd/scan.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"vajra/internal/analyzer"
	"vajra/internal/db"
	"vajra/internal/db/queries"
	"vajra/internal/jobs"
	"vajra/internal/scanner"
	"vajra/internal/utilities"
)

var scanCmd = &cobra.Command{
	Use:   "scan [directory]",
	Short: "Run a full YARA scan on the filesystem",
	Long: `Walks the target directory, submits every eligible file through the
YARA pipeline, and writes detections to the database.

If [directory] is omitted the target_directory from config is used.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	cfg, err := utilities.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("scan: load config: %w", err)
	}

	logger := utilities.GetLogger(cfg)

	sysInfo, err := utilities.LoadSystemInfo()
	if err != nil {
		return fmt.Errorf("scan: load system info: %w", err)
	}

	targetDir := cfg.ScanSettings.TargetDirectory
	if len(args) == 1 && args[0] != "" {
		targetDir = args[0]
	}

	if _, err := os.Stat(targetDir); err != nil {
		return fmt.Errorf("scan: target directory %q: %w", targetDir, err)
	}

	dbPath := filepath.Join(cfg.GenericSettings.DBDirectory, cfg.GenericSettings.DBFilename)
	database, err := db.Open(dbPath, logger)
	if err != nil {
		return fmt.Errorf("scan: open db: %w", err)
	}
	defer database.Close()

	fq := queries.NewFileQueries(database)

	rulesCompiler := scanner.NewRulesCompiler(logger)

	extractDir := filepath.Join(cfg.GenericSettings.WorkDirectory, "rules-extracted")
	if err := rulesCompiler.ExtractRules(cfg.RulesSettings.RulesFilepath, extractDir); err != nil {
		return fmt.Errorf("scan: extract rules: %w", err)
	}

	rules, err := rulesCompiler.CompileRules(extractDir)
	if err != nil {
		return fmt.Errorf("scan: compile rules: %w", err)
	}

	pool := scanner.NewPool(
		rules,
		cfg.PerformanceSettings.DefaultThreads,
		cfg.PerformanceSettings.MaxAllowedThreads,
		cfg.PerformanceSettings.ScanQueueSize,
		cfg.TimingSettings.SingleFileScanTimeoutSec,
		logger,
	)
	defer pool.Stop()

	cache := analyzer.NewResultCache()
	yaraAnalyzer := analyzer.NewYARAAnalyzer(pool, logger)
	pipeline := analyzer.NewPipeline([]analyzer.Analyzer{yaraAnalyzer}, analyzer.WithCache(cache))

	filter := scanner.NewExclusionFilter(&cfg)
	dedup := scanner.NewDedupTracker(time.Duration(cfg.TimingSettings.DedupWindowMin) * time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nscan interrupted, finishing current file...")
		cancel()
	}()

	fmt.Printf("Starting scan: %s\n\n", targetDir)
	start := time.Now()

	summary, err := jobs.RunFullScan(ctx, targetDir, pipeline, filter, dedup, fq, sysInfo, logger)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	elapsed := time.Since(start).Round(time.Second)

	if summary.Interrupted {
		fmt.Printf("Scan interrupted after %s: %s files scanned, %s hits found\n",
			elapsed,
			formatCount(summary.FilesScanned),
			formatCount(summary.HitsFound),
		)
	} else {
		fmt.Printf("Scan complete in %s: %s files scanned, %s hits found\n",
			elapsed,
			formatCount(summary.FilesScanned),
			formatCount(summary.HitsFound),
		)
	}

	return nil
}

// formatCount formats an int64 with thousands separators for readability.
func formatCount(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}

	out := make([]byte, 0, len(s)+len(s)/3)
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}
