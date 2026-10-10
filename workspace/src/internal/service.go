// internal/service.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package internal

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"vajra/internal/analyzer"
	"vajra/internal/db"
	"vajra/internal/db/queries"
	"vajra/internal/detect"
	"vajra/internal/detect/autorun"
	"vajra/internal/ebpf"
	"vajra/internal/findings"
	"vajra/internal/job"
	"vajra/internal/scanner/yara"
	"vajra/internal/utilities"
	"vajra/internal/watcher"
)

func startServiceMode(logger *zerolog.Logger, cfg *utilities.Config, database *db.DB, sysInfo utilities.SystemInfo) {
	logger.Info().Msg("starting monitoring mode")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	wireAll(ctx, &wg, logger, cfg, database, sysInfo)

	logger.Info().Msg("monitoring active — press Ctrl+C to stop")
	<-sigChan
	logger.Info().Msg("shutting down...")
	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info().Msg("clean shutdown complete")
	case <-time.After(time.Duration(cfg.TimingSettings.ShutdownTimeoutSec) * time.Second):
		logger.Warn().Msg("shutdown timeout exceeded, forcing exit")
	}
}

func wireAll(
	ctx context.Context,
	wg *sync.WaitGroup,
	logger *zerolog.Logger,
	cfg *utilities.Config,
	database *db.DB,
	sysInfo utilities.SystemInfo,
) {
	// ── YARA rules ────────────────────────────────────────────
	compiler := yara.NewCompiler(logger)
	extractionPath := filepath.Join(cfg.GenericSettings.WorkDirectory, "rules")
	if err := compiler.ExtractRules(cfg.RulesSettings.RulesFilepath, extractionPath); err != nil {
		logger.Fatal().Err(err).Msg("failed to extract YARA rules")
	}
	yaraRules, err := compiler.CompileRules(extractionPath)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to compile YARA rules")
	}
	pool := yara.NewPool(
		yaraRules,
		cfg.PerformanceSettings.DefaultThreads,
		cfg.PerformanceSettings.MaxAllowedThreads,
		cfg.PerformanceSettings.ScanQueueSize,
		cfg.TimingSettings.SingleFileScanTimeoutSec,
		logger,
	)

	// ── Shared infrastructure ─────────────────────────────────
	exclusionFilter := utilities.NewExclusionFilter(cfg)
	processFilter := utilities.NewProcessFilter(cfg)
	resultCache := analyzer.NewResultCache()
	dedupWindow := time.Duration(cfg.TimingSettings.DedupWindowMin) * time.Minute

	// Shared tracker — injected into both ProcessScanner and RunProcWalk so
	// a binary scanned at startup is not re-evaluated when it later execves.
	processTracker := utilities.NewRecentScanTracker(
		time.Duration(cfg.TimingSettings.DedupWindowMin) * time.Minute,
	)

	// ── FindingWriter — single DB insertion point ─────────────
	fw := findings.NewFindingWriter(
		logger,
		queries.NewDetectionQueries(database),
		queries.NewArtifactQueries(database),
		queries.NewDetectionNetworkQueries(database),
		queries.NewSecretQueries(database),
		queries.NewExtensionQueries(database),
		queries.NewEvidenceQueries(database),
		dedupWindow,
		sysInfo,
	)

	// ── Analyzer pipelines ────────────────────────────────────

	hashAnalyzer, err := analyzer.NewHashAnalyzer(cfg.ThreatIntelSettings.BloomFilterPath, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to load hash analyzer")
	}

	contentPipeline := analyzer.NewPipeline(
		[]analyzer.Analyzer{hashAnalyzer, analyzer.NewYARAAnalyzer(pool, logger)},
		analyzer.WithCache(resultCache),
	)

	runtimePipeline := analyzer.NewPipeline(
		[]analyzer.Analyzer{
			analyzer.NewLDPreloadAnalyzer(logger),
			analyzer.NewCapabilityAnalyzer(logger),
		},
	)

	// ── eBPF listener and dispatcher ──────────────────────────
	channels := ebpf.NewChannels(cfg.PerformanceSettings.ScanQueueSize)
	listener, err := ebpf.NewListener(logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create eBPF listener")
	}
	rawCh := make(chan ebpf.RawEvent, cfg.PerformanceSettings.ScanQueueSize)
	if err := listener.Start(ctx, rawCh); err != nil {
		logger.Fatal().Err(err).Msg("failed to start eBPF listener")
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		listener.Stop()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ebpf.NewDispatcher(logger).Run(ctx, rawCh, channels)
	}()

	// Drain namespace channel — events translated to SecurityEvent upstream.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-channels.Namespace:
				if !ok {
					return
				}
			}
		}
	}()

	// ── Watchers ──────────────────────────────────────────────
	watcher.NewEventSink(
		logger,
		queries.NewNetworkQueries(database),
		queries.NewMemoryQueries(database),
		queries.NewSecurityQueries(database),
		sysInfo,
	).Run(ctx, wg, channels)

	wg.Add(1)
	go watcher.NewDupWatcher(logger, fw, sysInfo).Run(ctx, wg, channels.Dup)

	wg.Add(1)
	go watcher.NewFileScanner(
		logger, contentPipeline, fw, exclusionFilter, sysInfo,
	).Run(ctx, wg, channels.File)

	wg.Add(1)
	go watcher.NewProcessScanner(
		logger, contentPipeline, runtimePipeline, fw,
		queries.NewProcessTreeQueries(database),
		processFilter,
		processTracker, // shared with RunProcWalk below
		sysInfo,
	).Run(ctx, wg, channels.Process)

	// ── Startup process walk ──────────────────────────────────
	// Runs once immediately to catch processes that pre-date agent startup.
	// Shares processTracker with ProcessScanner — binaries scanned here are
	// not re-scanned when they next execve.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := detect.RunProcWalk(
			ctx,
			contentPipeline,
			fw,
			processFilter,
			processTracker,
			sysInfo,
			logger,
		)
		if err != nil && ctx.Err() == nil {
			logger.Error().Err(err).Msg("procwalk: startup walk failed")
		}
	}()

	// ── Scanners ──────────────────────────────────────────────
	wg.Add(1)
	go autorun.NewScanner(
		logger,
		queries.NewAutorunQueries(database),
		fw,
		sysInfo,
		cfg.TimingSettings.AutorunScanTimeMin,
	).Run(ctx, wg)

	secretsScanner, err := detect.NewSecretsScanner(logger, fw, sysInfo, cfg)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create secrets scanner")
	}
	wg.Add(1)
	go secretsScanner.Run(ctx, wg)

	// ── Jobs ──────────────────────────────────────────────────
	go job.NewCleanup(
		logger,
		queries.NewCleanupQueries(database),
		cfg.TimingSettings.DatabaseCleanupTimeHour,
		cfg.TimingSettings.DatabaseRetentionDays,
	).Run(ctx, wg)

	wg.Add(1)
	go job.NewRuleSyncer(logger, cfg.RulesSettings).Run(ctx, wg)

	wg.Add(1)
	go job.NewHashSyncer(logger, cfg.ThreatIntelSettings).Run(ctx, wg)
}
