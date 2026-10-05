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
	"vajra/internal/ebpf"
	"vajra/internal/jobs"
	"vajra/internal/jobs/autoruns"
	"vajra/internal/procanalyzer"
	"vajra/internal/scanner"
	"vajra/internal/utilities"
)

func startServiceMode(logger *zerolog.Logger, cfg *utilities.Config, database *db.DB, sysInfo utilities.SystemInfo) {
	logger.Info().Msg("starting monitoring mode")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	wireJobs(ctx, &wg, logger, cfg, database, sysInfo)

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

func wireJobs(
	ctx context.Context,
	wg *sync.WaitGroup,
	logger *zerolog.Logger,
	cfg *utilities.Config,
	database *db.DB,
	sysInfo utilities.SystemInfo,
) {
	rulesCompiler := scanner.NewRulesCompiler(logger)
	extractionPath := filepath.Join(cfg.GenericSettings.WorkDirectory, "rules")

	if err := rulesCompiler.ExtractRules(cfg.RulesSettings.RulesFilepath, extractionPath); err != nil {
		logger.Fatal().Err(err).Msg("failed to extract YARA rules")
	}
	yaraRules, err := rulesCompiler.CompileRules(extractionPath)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to compile YARA rules")
	}

	pool := scanner.NewPool(
		yaraRules,
		cfg.PerformanceSettings.DefaultThreads,
		cfg.PerformanceSettings.MaxAllowedThreads,
		cfg.PerformanceSettings.ScanQueueSize,
		cfg.TimingSettings.SingleFileScanTimeoutSec,
		logger,
	)

	exclusionFilter := scanner.NewExclusionFilter(cfg)
	processFilter := scanner.NewProcessFilter(cfg)
	resultCache := analyzer.NewResultCache()

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

	// Namespace channel drain — namespace events are translated to
	// SecurityEvent upstream; this guards against future dispatcher changes.
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

	wg.Add(1)
	go jobs.RunDBCleanup(ctx, wg, logger,
		queries.NewCleanupQueries(database),
		cfg.TimingSettings.DatabaseCleanupTimeHour,
		cfg.TimingSettings.DatabaseRetentionDays,
	)

	wg.Add(1)
	go autoruns.RunAutorunScan(ctx, wg, logger, database, cfg.TimingSettings.AutorunScanTimeMin)

	jobs.NewEventSink(
		logger,
		queries.NewNetworkQueries(database),
		queries.NewMemoryQueries(database),
		queries.NewSecurityQueries(database),
		sysInfo,
	).Run(ctx, wg, channels)

	// DupWatcher — reverse shell detection via dup2/dup3 onto stdio.
	// Reads from channels.Dup directly, writes CRITICAL to security_events
	// on confirmed network socket redirection. No pipeline, no comm filtering.
	wg.Add(1)
	go jobs.NewDupWatcher(
		logger,
		queries.NewSecurityQueries(database),
		sysInfo,
	).Run(ctx, wg, channels.Dup)

	wg.Add(1)
	go jobs.NewRuleSyncer(logger, cfg.RulesSettings).Run(ctx, wg)

	wirePipelines(ctx, wg, logger, cfg, database, pool, exclusionFilter, processFilter, resultCache, channels, sysInfo)
}

func wirePipelines(
	ctx context.Context,
	wg *sync.WaitGroup,
	logger *zerolog.Logger,
	cfg *utilities.Config,
	database *db.DB,
	pool *scanner.Pool,
	exclusionFilter *scanner.ExclusionFilter,
	processFilter *scanner.ProcessFilter,
	resultCache *analyzer.ResultCache,
	channels *ebpf.Channels,
	sysInfo utilities.SystemInfo,
) {
	dedupWindow := time.Duration(cfg.TimingSettings.DedupWindowMin) * time.Minute

	filePipeline := analyzer.NewPipeline(
		[]analyzer.Analyzer{analyzer.NewYARAAnalyzer(pool, logger)},
		analyzer.WithCache(resultCache),
	)

	contentPipeline := analyzer.NewPipeline(
		[]analyzer.Analyzer{analyzer.NewYARAAnalyzer(pool, logger)},
		analyzer.WithCache(resultCache),
	)

	// Runtime pipeline — always runs regardless of process exclusion filter.
	// RevShellAnalyzer removed: reverse shell detection is now driven by
	// dup2/dup3 events in DupWatcher, which catches the bash -i >& /dev/tcp/...
	// pattern that exec-time fd inspection could not see.
	runtimePipeline := analyzer.NewPipeline(
		[]analyzer.Analyzer{
			procanalyzer.NewLDPreloadAnalyzer(logger),
			procanalyzer.NewCapabilityAnalyzer(logger),
		},
	)

	fileScanner := jobs.NewFileScanner(
		logger, filePipeline,
		queries.NewFileQueries(database),
		exclusionFilter, dedupWindow,
		sysInfo,
	)
	wg.Add(1)
	go fileScanner.Run(ctx, wg, channels.File)

	processScanner := jobs.NewProcessScanner(
		logger,
		contentPipeline,
		runtimePipeline,
		queries.NewProcessQueries(database),
		queries.NewProcessTreeQueries(database),
		processFilter,
		dedupWindow,
		sysInfo,
	)
	wg.Add(1)
	go processScanner.Run(ctx, wg, channels.Process)
}
