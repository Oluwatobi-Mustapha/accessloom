package scheduler

import (
	"context"
	"errors"
	"time"
)

// ErrAlreadyRunning indicates a scheduled scan trigger was skipped due to an in-flight run.
var ErrAlreadyRunning = errors.New("scan already running")

// TriggerFunc runs one scheduled scan iteration.
type TriggerFunc func(context.Context) error

// Runner periodically executes a trigger while enforcing single-flight per key.
type Runner struct {
	Interval time.Duration
	Key      string
	Locker   Locker
	Trigger  TriggerFunc
}

// RunOnce triggers a scan exactly once.
func (r Runner) RunOnce(ctx context.Context) error {
	if r.Trigger == nil {
		return errors.New("runner trigger is required")
	}

	if r.Locker != nil {
		release, ok := r.Locker.TryAcquire(r.key())
		if !ok {
			return ErrAlreadyRunning
		}
		defer release()
	}

	return r.Trigger(ctx)
}

// Start runs the scheduler loop until context cancellation.
func (r Runner) Start(ctx context.Context) error {
	if r.Interval <= 0 {
		return errors.New("runner interval must be greater than zero")
	}
	if r.Trigger == nil {
		return errors.New("runner trigger is required")
	}

	ticker := time.NewTicker(r.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_ = r.RunOnce(ctx)
		}
	}
}

func (r Runner) key() string {
	if r.Key == "" {
		return "scan"
	}
	return r.Key
}
