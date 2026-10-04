// internal/service.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
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
	"vajra/internal/db"
	"vajra/internal/db/queries"
	"vajra/internal/ebpf"
	"vajra/internal/jobs"
	"vajra/internal/jobs/autoruns"
	"vajra/internal/scanner"
	"vajra/internal/utilities"
)

func startServiceMode(logger *zerolog.Logger, cfg *utilities.Config, database *db.DB) {
	logger.Info().Msg("starting monitoring mode")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// ── YARA rule compilation ─────────────────────────────────
	rulesCompiler := scanner.NewRulesCompiler(logger)
	extractionPath := filepath.Join(cfg.GenericSettings.WorkDirectory, "rules")

	if err := rulesCompiler.ExtractRules(cfg.ScanSettings.RulesFilepath, extractionPath); err != nil {
		logger.Fatal().Err(err).Msg("failed to extract YARA rules")
	}

	yaraRules, err := rulesCompiler.CompileRules(extractionPath)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to compile YARA rules")
	}

	// ── Scanner pool ──────────────────────────────────────────
	pool := scanner.NewPool(
		yaraRules,
		cfg.PerformanceSettings.DefaultThreads,
		cfg.PerformanceSettings.MaxAllowedThreads,
		cfg.PerformanceSettings.ScanQueueSize,
		cfg.TimingSettings.SingleFileScanTimeoutSec,
		logger,
	)
	defer pool.Stop()

	// ── Shared filters ────────────────────────────────────────
	exclusionFilter := scanner.NewExclusionFilter(cfg)
	processFilter := scanner.NewProcessFilter(cfg)

	// ── eBPF typed channel bundle ─────────────────────────────
	// Buffer depth matches the YARA pool queue size so neither
	// side starves the other under burst load.
	channels := ebpf.NewChannels(cfg.PerformanceSettings.ScanQueueSize)

	// ── eBPF listener ─────────────────────────────────────────
	listener, err := ebpf.NewListener(logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create eBPF listener")
	}
	defer listener.Stop()

	// rawCh sits between listener and dispatcher.
	// Same buffer depth as the typed channels.
	rawCh := make(chan ebpf.RawEvent, cfg.PerformanceSettings.ScanQueueSize)

	if err := listener.Start(ctx, rawCh); err != nil {
		logger.Fatal().Err(err).Msg("failed to start eBPF listener")
	}

	// ── eBPF dispatcher ───────────────────────────────────────
	dispatcher := ebpf.NewDispatcher(logger)
	wg.Add(1)
	go func() {
		defer wg.Done()
		dispatcher.Run(ctx, rawCh, channels)
	}()

	// ── DB cleanup job ────────────────────────────────────────
	wg.Add(1)
	go jobs.RunDBCleanup(
		ctx,
		&wg,
		logger,
		queries.NewCleanupQueries(database),
		cfg.TimingSettings.DatabaseCleanupTimeHour,
		cfg.TimingSettings.DatabaseRetentionDays,
	)

	// ── Autorun scanner job ───────────────────────────────────
	wg.Add(1)
	go autoruns.RunAutorunScan(
		ctx,
		&wg,
		logger,
		database,
		cfg.TimingSettings.AutorunScanTimeMin,
	)
	jobs.DrainChannels(ctx, &wg, logger, channels)
	// ── File scanner job ──────────────────────────────────────
	fileScanner := jobs.NewFileScanner(
		logger,
		pool,
		queries.NewFileQueries(database),
		exclusionFilter,
	)
	wg.Add(1)
	go fileScanner.Run(ctx, &wg, channels.File)

	// ── Process scanner job ───────────────────────────────────
	processScanner := jobs.NewProcessScanner(
		logger,
		pool,
		queries.NewProcessQueries(database),
		processFilter,
	)
	wg.Add(1)
	go processScanner.Run(ctx, &wg, channels.Process)

	logger.Info().Msg("monitoring active — press Ctrl+C to stop")

	select {
	case sig := <-sigChan:
		logger.Info().Str("signal", sig.String()).Msg("shutdown signal received")
	}

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
