// internal/job/job.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package job

import (
	"context"
	"sync"
)

// Job is a utility goroutine with no detection role.
// Cleanup, rule sync, aggregation — anything that supports
// the system without producing findings belongs here.
type Job interface {
	Name() string
	Run(ctx context.Context, wg *sync.WaitGroup)
}
