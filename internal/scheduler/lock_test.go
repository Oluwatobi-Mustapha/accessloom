package scheduler

import "testing"

func TestInMemoryLockerTryAcquire(t *testing.T) {
	locker := NewInMemoryLocker()

	release, ok := locker.TryAcquire("scan:aws")
	if !ok || release == nil {
		t.Fatal("expected first acquire success")
	}

	if _, ok := locker.TryAcquire("scan:aws"); ok {
		t.Fatal("expected lock contention")
	}

	release()
	if _, ok := locker.TryAcquire("scan:aws"); !ok {
		t.Fatal("expected acquire after release")
	}
}

func TestInMemoryLockerReleaseIdempotent(t *testing.T) {
	locker := NewInMemoryLocker()
	release, ok := locker.TryAcquire("scan:aws")
	if !ok {
		t.Fatal("expected acquire success")
	}
	release()
	release()

	if _, ok := locker.TryAcquire("scan:aws"); !ok {
		t.Fatal("expected acquire after double release")
	}
}
