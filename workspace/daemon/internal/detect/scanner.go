// internal/detect/scanner.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package detect

import (
	"context"
	"sync"
)

// Scanner pulls from a data source and produces findings.
// All scanners are pull-based — they walk a filesystem, /proc,
// or system state on a timer or at startup. The data source is
// injected at construction time, not through this interface.
type Scanner interface {
	Name() string
	Run(ctx context.Context, wg *sync.WaitGroup)
}
