// internal/jobs/drainer.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package jobs

import (
	"context"
	"sync"

	"github.com/rs/zerolog"
	"vajra/internal/ebpf"
)

// DrainChannels reads and discards events from channels that do
// not yet have a real consumer. This prevents the dispatcher from
// dropping events simply because a channel buffer is full.
//
// Each channel gets its own goroutine added to wg so shutdown
// is clean — all drainers stop when ctx is cancelled.
//
// Replace individual drain calls with real job wiring as each
// consumer is implemented. Delete this file when all channels
// have real consumers.
func DrainChannels(
	ctx context.Context,
	wg *sync.WaitGroup,
	logger *zerolog.Logger,
	ch *ebpf.Channels,
) {
	drainMemory(ctx, wg, logger, ch.Memory)
	drainNetwork(ctx, wg, logger, ch.Network)
	drainSecurity(ctx, wg, logger, ch.Security)
	drainModule(ctx, wg, logger, ch.Module)
	drainNamespace(ctx, wg, logger, ch.Namespace)
}

func drainMemory(
	ctx context.Context,
	wg *sync.WaitGroup,
	logger *zerolog.Logger,
	ch <-chan ebpf.MmapEvent,
) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-ch:
				if !ok {
					return
				}
				logger.Debug().
					Uint32("pid", e.PID).
					Uint32("type", e.Type).
					Uint64("addr", e.Addr).
					Uint32("prot", e.Prot).
					Msg("drain: memory event discarded (no consumer yet)")
			}
		}
	}()
}

func drainNetwork(
	ctx context.Context,
	wg *sync.WaitGroup,
	logger *zerolog.Logger,
	ch <-chan ebpf.NetworkEvent,
) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-ch:
				if !ok {
					return
				}
				// Network events are high volume — no logging even at debug.
			}
		}
	}()
}

func drainSecurity(
	ctx context.Context,
	wg *sync.WaitGroup,
	logger *zerolog.Logger,
	ch <-chan ebpf.SecurityEvent,
) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-ch:
				if !ok {
					return
				}
				logger.Debug().
					Uint32("pid", e.PID).
					Str("event", e.EventName).
					Msg("drain: security event discarded (no consumer yet)")
			}
		}
	}()
}

func drainModule(
	ctx context.Context,
	wg *sync.WaitGroup,
	logger *zerolog.Logger,
	ch <-chan ebpf.ModuleEvent,
) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-ch:
				if !ok {
					return
				}
				// Module loads are rare — always log even while draining.
				logger.Warn().
					Uint32("pid", e.PID).
					Str("name", ebpf.CStringToGo(e.Name[:])).
					Msg("drain: kernel module load detected (no consumer yet)")
			}
		}
	}()
}

func drainNamespace(
	ctx context.Context,
	wg *sync.WaitGroup,
	logger *zerolog.Logger,
	ch <-chan ebpf.NamespaceEvent,
) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-ch:
				if !ok {
					return
				}
				logger.Debug().
					Uint32("pid", e.PID).
					Uint32("type", e.Type).
					Msg("drain: namespace event discarded (no consumer yet)")
			}
		}
	}()
}
