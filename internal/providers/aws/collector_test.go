package aws

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeIAMClient struct {
	listFn func(ctx context.Context, nextToken string, pageSize int32) (ListRolesPage, error)
	calls  int
}

func (f *fakeIAMClient) ListRoles(ctx context.Context, nextToken string, pageSize int32) (ListRolesPage, error) {
	f.calls++
	return f.listFn(ctx, nextToken, pageSize)
}

type fakeRetryableError struct {
	message string
}

func (f fakeRetryableError) Error() string   { return f.message }
func (f fakeRetryableError) Retryable() bool { return true }

func TestCollectFromFixturesPaginationAndDedup(t *testing.T) {
	page1 := mustLoadPageFixture(t, "list_roles_page_1.json")
	page2 := mustLoadPageFixture(t, "list_roles_page_2.json")

	calls := 0
	client := &fakeIAMClient{
		listFn: func(_ context.Context, nextToken string, pageSize int32) (ListRolesPage, error) {
			calls++
			if pageSize != 2 {
				t.Fatalf("expected page size 2, got %d", pageSize)
			}
			switch calls {
			case 1:
				if nextToken != "" {
					t.Fatalf("expected empty token on first call, got %q", nextToken)
				}
				return page1, nil
			case 2:
				if nextToken != "token-2" {
					t.Fatalf("expected token-2 on second call, got %q", nextToken)
				}
				return page2, nil
			default:
				t.Fatalf("unexpected call %d", calls)
				return ListRolesPage{}, nil
			}
		},
	}

	fixedNow := time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC)
	collector := NewCollector(
		client,
		WithPageSize(2),
		WithClock(func() time.Time { return fixedNow }),
	)

	assets, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 3 {
		t.Fatalf("expected 3 deduplicated assets, got %d", len(assets))
	}

	if assets[0].Kind != "iam_role" {
		t.Fatalf("unexpected asset kind: %q", assets[0].Kind)
	}
	if assets[0].Collected != "2026-03-16T00:00:00Z" {
		t.Fatalf("unexpected collected timestamp: %q", assets[0].Collected)
	}

	var role IAMRole
	if err := json.Unmarshal(assets[0].Payload, &role); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if role.ARN == "" || role.Name == "" {
		t.Fatalf("unexpected role payload: %+v", role)
	}
}

func TestCollectRetriesOnThrottleThenSucceeds(t *testing.T) {
	attempt := 0
	delays := make([]time.Duration, 0, 2)

	client := &fakeIAMClient{
		listFn: func(_ context.Context, _ string, _ int32) (ListRolesPage, error) {
			attempt++
			if attempt <= 2 {
				return ListRolesPage{}, fakeRetryableError{message: "Throttling: Rate exceeded"}
			}
			return ListRolesPage{Roles: []IAMRole{{ARN: "arn:aws:iam::123:role/app", Name: "app"}}}, nil
		},
	}

	collector := NewCollector(
		client,
		WithRetryPolicy(RetryPolicy{MaxRetries: 3, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond}),
		WithRetryJitterRatio(0),
		WithSleeper(func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		}),
	)

	assets, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	if len(delays) != 2 {
		t.Fatalf("expected 2 retry delays, got %d", len(delays))
	}
	if delays[0] != time.Millisecond || delays[1] != 2*time.Millisecond {
		t.Fatalf("unexpected retry delays: %+v", delays)
	}
}

func TestCollectRetryBackoffJitterApplied(t *testing.T) {
	attempt := 0
	delays := make([]time.Duration, 0, 2)

	client := &fakeIAMClient{
		listFn: func(_ context.Context, _ string, _ int32) (ListRolesPage, error) {
			attempt++
			if attempt <= 2 {
				return ListRolesPage{}, fakeRetryableError{message: "Throttling"}
			}
			return ListRolesPage{Roles: []IAMRole{{ARN: "arn:aws:iam::123:role/app", Name: "app"}}}, nil
		},
	}

	collector := NewCollector(
		client,
		WithRetryPolicy(RetryPolicy{MaxRetries: 3, BaseDelay: 100 * time.Millisecond, MaxDelay: 500 * time.Millisecond}),
		WithRetryJitterRatio(0.25),
		WithRetryRandFunc(func() float64 { return 1.0 }),
		WithSleeper(func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		}),
	)

	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(delays) != 2 {
		t.Fatalf("expected 2 retry delays, got %d", len(delays))
	}
	if delays[0] != 125*time.Millisecond || delays[1] != 250*time.Millisecond {
		t.Fatalf("expected jittered delays [125ms 250ms], got %+v", delays)
	}
}

func TestCollectRetryExhausted(t *testing.T) {
	client := &fakeIAMClient{
		listFn: func(_ context.Context, _ string, _ int32) (ListRolesPage, error) {
			return ListRolesPage{}, fakeRetryableError{message: "Throttling"}
		},
	}

	collector := NewCollector(client, WithRetryPolicy(RetryPolicy{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}))
	_, err := collector.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "retries exhausted") {
		t.Fatalf("expected retries exhausted error, got: %v", err)
	}
}

func TestCollectNonRetryableError(t *testing.T) {
	calls := 0
	client := &fakeIAMClient{
		listFn: func(_ context.Context, _ string, _ int32) (ListRolesPage, error) {
			calls++
			return ListRolesPage{}, errors.New("access denied")
		},
	}

	collector := NewCollector(client, WithRetryPolicy(RetryPolicy{MaxRetries: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}))
	_, err := collector.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("expected one call for non-retryable error, got %d", calls)
	}
}

func TestCollectStopsWhenContextCancelledDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	client := &fakeIAMClient{
		listFn: func(_ context.Context, _ string, _ int32) (ListRolesPage, error) {
			return ListRolesPage{}, fakeRetryableError{message: "Throttling"}
		},
	}

	collector := NewCollector(
		client,
		WithRetryPolicy(RetryPolicy{MaxRetries: 3, BaseDelay: time.Second, MaxDelay: time.Second}),
		WithSleeper(func(_ context.Context, _ time.Duration) error {
			cancel()
			return context.Canceled
		}),
	)

	_, err := collector.Collect(ctx)
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("expected canceled error, got: %v", err)
	}
}

func TestCollectMaxPagesGuard(t *testing.T) {
	client := &fakeIAMClient{
		listFn: func(_ context.Context, _ string, _ int32) (ListRolesPage, error) {
			return ListRolesPage{NextToken: "more"}, nil
		},
	}

	collector := NewCollector(client, WithMaxPages(1))
	_, err := collector.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "exceeded max pages") {
		t.Fatalf("expected max pages error, got: %v", err)
	}
}

func TestCollectFailsWithoutClient(t *testing.T) {
	collector := NewCollector(nil)
	_, err := collector.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestIsRetryableByMessage(t *testing.T) {
	if !isRetryable(errors.New("RequestLimitExceeded")) {
		t.Fatal("expected retryable error")
	}
	if isRetryable(errors.New("permission denied")) {
		t.Fatal("expected non-retryable error")
	}
}

func mustLoadPageFixture(t *testing.T, name string) ListRolesPage {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testdata", "aws", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}

	type fixtureRole struct {
		ARN                      string            `json:"arn"`
		Name                     string            `json:"name"`
		Path                     string            `json:"path"`
		AssumeRolePolicyDocument string            `json:"assume_role_policy_document"`
		Description              string            `json:"description"`
		CreatedAt                string            `json:"created_at"`
		LastUsedAt               string            `json:"last_used_at"`
		MaxSessionDuration       int32             `json:"max_session_duration"`
		Tags                     map[string]string `json:"tags"`
	}
	type fixturePage struct {
		NextToken string        `json:"next_token"`
		Roles     []fixtureRole `json:"roles"`
	}

	var page fixturePage
	if err := json.Unmarshal(data, &page); err != nil {
		t.Fatalf("decode fixture %s: %v", path, err)
	}

	roles := make([]IAMRole, 0, len(page.Roles))
	for _, role := range page.Roles {
		var createdAt *time.Time
		if role.CreatedAt != "" {
			parsed, err := time.Parse(time.RFC3339, role.CreatedAt)
			if err != nil {
				t.Fatalf("parse created_at in %s: %v", path, err)
			}
			createdAt = &parsed
		}

		var lastUsedAt *time.Time
		if role.LastUsedAt != "" {
			parsed, err := time.Parse(time.RFC3339, role.LastUsedAt)
			if err != nil {
				t.Fatalf("parse last_used_at in %s: %v", path, err)
			}
			lastUsedAt = &parsed
		}

		roles = append(roles, IAMRole{
			ARN:                      role.ARN,
			Name:                     role.Name,
			Path:                     role.Path,
			AssumeRolePolicyDocument: role.AssumeRolePolicyDocument,
			Description:              role.Description,
			CreatedAt:                createdAt,
			LastUsedAt:               lastUsedAt,
			MaxSessionDuration:       role.MaxSessionDuration,
			Tags:                     role.Tags,
		})
	}

	return ListRolesPage{Roles: roles, NextToken: page.NextToken}
}
