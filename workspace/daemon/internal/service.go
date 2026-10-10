// internal/service.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package internal

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"vajra/internal/analyzer"
	"vajra/internal/db/queries"
	"vajra/internal/detect"
	"vajra/internal/detect/autorun"
	"vajra/internal/ebpf"
	"vajra/internal/findings"
	"vajra/internal/job"
	"vajra/internal/scanner/yara"
	"vajra/internal/utilities"
	"vajra/internal/watcher"

	"github.com/rs/zerolog"

	sharedconfig "vajra/shared/config"
	shareddb "vajra/shared/db"
)

// shutdownTimeout is the maximum time allowed for goroutines to stop cleanly.
const shutdownTimeout = 30 * time.Second

func startServiceMode(logger *zerolog.Logger, cfg *sharedconfig.Config, database *shareddb.DB, sysInfo utilities.SystemInfo) {
	logger.Info().Msg("starting monitoring mode")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	// J13: signal.Stop was never called — deferred here so the channel is
	// drained and the goroutine can be collected when the process exits.
	defer signal.Stop(sigChan)

	// J12: wireAll returns an error instead of calling Fatal after goroutines
	// have started. If wiring fails, cancel shuts down any goroutines that
	// did start before the failure.
	if err := wireAll(ctx, &wg, logger, cfg, database, sysInfo); err != nil {
		logger.Error().Err(err).Msg("startup failed")
		cancel()
		wg.Wait()
		return
	}

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
	case <-time.After(shutdownTimeout):
		logger.Warn().Msg("shutdown timeout exceeded, forcing exit")
	}
}

func wireAll(
	ctx context.Context,
	wg *sync.WaitGroup,
	logger *zerolog.Logger,
	cfg *sharedconfig.Config,
	database *shareddb.DB,
	sysInfo utilities.SystemInfo,
) error {
	// ── YARA rules ────────────────────────────────────────────
	compiler := yara.NewCompiler(logger, cfg.ScanSettings.MaxFileSizeBytes)
	extractionPath := filepath.Join(cfg.GenericSettings.WorkDirectory, "rules")
	if err := compiler.ExtractRules(cfg.RulesSettings.RulesFilepath, extractionPath); err != nil {
		return fmt.Errorf("extract YARA rules: %w", err)
	}
	yaraRules, err := compiler.CompileRules(extractionPath)
	if err != nil {
		return fmt.Errorf("compile YARA rules: %w", err)
	}
	pool := yara.NewPool(
		yaraRules,
		cfg.PerformanceSettings.DefaultThreads,
		cfg.PerformanceSettings.MaxAllowedThreads,
		cfg.PerformanceSettings.ScanQueueSize,
		cfg.TimingSettings.SingleFileScanTimeoutSec,
		cfg.ScanSettings.YaraSnapshotBytes,
		logger,
	)

	// ── Shared infrastructure ─────────────────────────────────
	exclusionFilter := utilities.NewExclusionFilter(cfg)
	processFilter := utilities.NewProcessFilter(cfg)
	dedupWindow := time.Duration(cfg.TimingSettings.DedupWindowMin) * time.Minute

	resultCache, err := analyzer.NewResultCache(cfg.PerformanceSettings.ResultCacheSize)
	if err != nil {
		return fmt.Errorf("create result cache: %w", err)
	}

	// Shared tracker — injected into both ProcessScanner and RunProcWalk so
	// a binary scanned at startup is not re-evaluated when it later execves.
	processTracker := utilities.NewRecentScanTracker(dedupWindow)

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
		return fmt.Errorf("load hash analyzer: %w", err)
	}

	contentPipeline := analyzer.NewPipeline(
		[]analyzer.Analyzer{hashAnalyzer, analyzer.NewYARAAnalyzer(pool, logger)},
		analyzer.WithCache(resultCache),
		analyzer.WithLogger(logger),
	)

	runtimePipeline := analyzer.NewPipeline(
		[]analyzer.Analyzer{
			analyzer.NewLDPreloadAnalyzer(logger, cfg.AlertPolicy),
			analyzer.NewCapabilityAnalyzer(logger, cfg.AlertPolicy),
		},
		analyzer.WithLogger(logger),
	)

	// ── eBPF listener and dispatcher ──────────────────────────
	channels := ebpf.NewChannels(cfg.PerformanceSettings.ScanQueueSize)
	listener, err := ebpf.NewListener(logger)
	if err != nil {
		return fmt.Errorf("create eBPF listener: %w", err)
	}
	rawCh := make(chan ebpf.RawEvent, cfg.PerformanceSettings.ScanQueueSize)
	if err := listener.Start(ctx, rawCh, cfg.PerformanceSettings.EBPFPerfRingPages); err != nil {
		return fmt.Errorf("start eBPF listener: %w", err)
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

	// Drain namespace channel — events are translated to SecurityEvent upstream.
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
		cfg.AlertPolicy,
	).Run(ctx, wg, channels)

	wg.Add(1)
	go watcher.NewDupWatcher(logger, fw, sysInfo).Run(ctx, wg, channels.Dup)

	wg.Add(1)
	go watcher.NewFileScanner(
		logger,
		contentPipeline,
		fw,
		exclusionFilter,
		sysInfo,
		cfg.ScanSettings.MaxFileSizeBytes,
		cfg.AlertPolicy.Interpreters,
	).Run(ctx, wg, channels.File)

	wg.Add(1)
	go watcher.NewProcessScanner(
		logger,
		contentPipeline,
		runtimePipeline,
		fw,
		queries.NewProcessTreeQueries(database),
		processFilter,
		processTracker,
		sysInfo,
	).Run(ctx, wg, channels.Process)

	// ── Startup process walk ──────────────────────────────────
	// Delayed to avoid a CPU spike while other system services are
	// still initialising. Shares processTracker with ProcessScanner.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !sleepWithCtx(ctx, time.Duration(cfg.TimingSettings.StartupProcwalkDelaySec)*time.Second) {
			return
		}
		if _, err := detect.RunProcWalk(ctx, contentPipeline, fw, processFilter, processTracker, sysInfo, logger); err != nil && ctx.Err() == nil {
			logger.Error().Err(err).Msg("procwalk: startup walk failed")
		}
	}()

	// ── Scanners ──────────────────────────────────────────────
	autorunScanner := autorun.NewScanner(
		logger,
		queries.NewAutorunQueries(database),
		fw,
		sysInfo,
		cfg.TimingSettings.AutorunScanIntervalMin,
		cfg.PerformanceSettings.AutorunConcurrency,
	)
	wg.Add(1)
	go func() {
		if !sleepWithCtx(ctx, time.Duration(cfg.TimingSettings.StartupAutorunDelaySec)*time.Second) {
			wg.Done()
			return
		}
		autorunScanner.Run(ctx, wg)
	}()

	secretsScanner, err := detect.NewSecretsScanner(logger, fw, sysInfo, cfg)
	if err != nil {
		return fmt.Errorf("create secrets scanner: %w", err)
	}
	wg.Add(1)
	go func() {
		if !sleepWithCtx(ctx, time.Duration(cfg.TimingSettings.StartupSecretsDelayMin)*time.Minute) {
			wg.Done()
			return
		}
		secretsScanner.Run(ctx, wg)
	}()

	// ── Jobs ──────────────────────────────────────────────────
	wg.Add(1)
	go job.NewCleanup(
		logger,
		queries.NewCleanupQueries(database),
		cfg.TimingSettings.CleanupIntervalHour,
		cfg.TimingSettings.EventRetentionDays,
	).Run(ctx, wg)

	wg.Add(1)
	go job.NewRuleSyncer(logger, cfg.RulesSettings).Run(ctx, wg)

	wg.Add(1)
	go job.NewHashSyncer(logger, cfg.ThreatIntelSettings, cfg.TimingSettings.HashSyncIntervalHour).Run(ctx, wg)

	wg.Add(1)
	go job.NewStatSyncer(logger, queries.NewStatisticsQueries(database), cfg.TimingSettings.StatsSyncIntervalMin).Run(ctx, wg)

	return nil
}

// sleepWithCtx blocks for d or until ctx is cancelled.
// Returns true if the full duration elapsed, false if ctx fired first.
// Used to implement startup delays without leaking goroutines on shutdown.
func sleepWithCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}
