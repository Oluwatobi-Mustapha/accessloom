package scheduler

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunnerRunOnce(t *testing.T) {
	var calls int32
	runner := Runner{
		Locker: NewInMemoryLocker(),
		Key:    "scan:aws",
		Trigger: func(context.Context) error {
			atomic.AddInt32(&calls, 1)
			return nil
		},
	}

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestRunnerRunOnceAlreadyRunning(t *testing.T) {
	locker := NewInMemoryLocker()
	release, ok := locker.TryAcquire("scan:aws")
	if !ok {
		t.Fatal("expected lock acquire")
	}
	defer release()

	runner := Runner{
		Locker:  locker,
		Key:     "scan:aws",
		Trigger: func(context.Context) error { return nil },
	}

	err := runner.RunOnce(context.Background())
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("expected ErrAlreadyRunning, got %v", err)
	}
}

func TestRunnerStartAndStop(t *testing.T) {
	var calls int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runner := Runner{
		Interval: 5 * time.Millisecond,
		Locker:   NewInMemoryLocker(),
		Key:      "scan:aws",
		Trigger: func(context.Context) error {
			if atomic.AddInt32(&calls, 1) >= 2 {
				cancel()
			}
			return nil
		},
	}

	err := runner.Start(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if calls < 2 {
		t.Fatalf("expected at least 2 calls, got %d", calls)
	}
}

func TestRunnerValidation(t *testing.T) {
	err := Runner{Trigger: nil, Interval: time.Second}.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected trigger validation error")
	}

	err = Runner{Trigger: func(context.Context) error { return nil }}.Start(context.Background())
	if err == nil {
		t.Fatal("expected interval validation error")
	}
}
