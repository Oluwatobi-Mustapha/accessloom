package scheduler

import (
	"context"
	"database/sql"
	"hash/fnv"
	"strings"
	"sync"
)

// PostgresAdvisoryLocker implements Locker using PostgreSQL advisory locks.
// A dedicated connection is held until release to keep lock ownership session-bound.
type PostgresAdvisoryLocker struct {
	db *sql.DB
}

// NewPostgresAdvisoryLocker builds a PostgreSQL-backed locker.
func NewPostgresAdvisoryLocker(db *sql.DB) *PostgresAdvisoryLocker {
	return &PostgresAdvisoryLocker{db: db}
}

// TryAcquire attempts to take a non-blocking advisory lock for key.
func (l *PostgresAdvisoryLocker) TryAcquire(key string) (ReleaseFn, bool) {
	if l == nil || l.db == nil {
		return nil, false
	}
	lockKey := advisoryLockID(key)
	conn, err := l.db.Conn(context.Background())
	if err != nil {
		return nil, false
	}

	var acquired bool
	if err := conn.QueryRowContext(context.Background(), "SELECT pg_try_advisory_lock($1)", lockKey).Scan(&acquired); err != nil {
		_ = conn.Close()
		return nil, false
	}
	if !acquired {
		_ = conn.Close()
		return nil, false
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", lockKey)
			_ = conn.Close()
		})
	}, true
}

func advisoryLockID(key string) int64 {
	normalized := strings.TrimSpace(key)
	if normalized == "" {
		normalized = "default"
	}
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(normalized))
	return int64(hasher.Sum64())
}
