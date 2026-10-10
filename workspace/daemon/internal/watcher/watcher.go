// internal/watcher/watcher.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package watcher

import (
	"context"
	"sync"
)

// Watcher consumes a pushed event stream and reacts to it.
// All watchers are push-based — they block on a channel until
// ctx is cancelled. The channel is injected at construction time,
// not through this interface, so the interface stays clean.
type Watcher interface {
	Name() string
	Run(ctx context.Context, wg *sync.WaitGroup)
}
