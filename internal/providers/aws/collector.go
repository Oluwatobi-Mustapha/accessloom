package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

const (
	defaultPageSize   int32 = 100
	defaultMaxPages         = 500
	defaultRetryCount       = 3
	defaultBaseDelay        = 200 * time.Millisecond
	defaultMaxDelay         = 3 * time.Second
)

// IAMRole represents the minimum AWS IAM role fields required for normalization.
type IAMRole struct {
	ARN                      string                `json:"arn"`
	Name                     string                `json:"name"`
	Path                     string                `json:"path,omitempty"`
	AssumeRolePolicyDocument string                `json:"assume_role_policy_document,omitempty"`
	PermissionPolicies       []IAMPermissionPolicy `json:"permission_policies,omitempty"`
	Description              string                `json:"description,omitempty"`
	CreatedAt                *time.Time            `json:"created_at,omitempty"`
	LastUsedAt               *time.Time            `json:"last_used_at,omitempty"`
	MaxSessionDuration       int32                 `json:"max_session_duration,omitempty"`
	Tags                     map[string]string     `json:"tags,omitempty"`
}

// ListRolesPage is one paged response from IAM ListRoles.
type ListRolesPage struct {
	Roles     []IAMRole
	NextToken string
}

// IAMAPI defines the subset of IAM operations required by the collector.
type IAMAPI interface {
	ListRoles(ctx context.Context, nextToken string, pageSize int32) (ListRolesPage, error)
}

// RetryPolicy controls retry behavior for transient API failures.
type RetryPolicy struct {
	MaxRetries int
	BaseDelay  time.Duration
	MaxDelay   time.Duration
}

// RetryableError can be implemented by provider errors that explicitly support retries.
type RetryableError interface {
	error
	Retryable() bool
}

// Sleeper abstracts sleep for deterministic tests.
type Sleeper func(ctx context.Context, delay time.Duration) error

// Collector collects IAM role assets in read-only mode.
type Collector struct {
	client   IAMAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	sleep    Sleeper
	now      func() time.Time
}

// Option customizes Collector behavior.
type Option func(*Collector)

// WithPageSize configures IAM pagination size.
func WithPageSize(pageSize int32) Option {
	return func(c *Collector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

// WithMaxPages limits list pagination to guard against runaways.
func WithMaxPages(maxPages int) Option {
	return func(c *Collector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

// WithRetryPolicy customizes retry strategy for transient IAM errors.
func WithRetryPolicy(policy RetryPolicy) Option {
	return func(c *Collector) {
		if policy.MaxRetries >= 0 {
			c.retry.MaxRetries = policy.MaxRetries
		}
		if policy.BaseDelay > 0 {
			c.retry.BaseDelay = policy.BaseDelay
		}
		if policy.MaxDelay > 0 {
			c.retry.MaxDelay = policy.MaxDelay
		}
	}
}

// WithSleeper injects a testable sleep function.
func WithSleeper(s Sleeper) Option {
	return func(c *Collector) {
		if s != nil {
			c.sleep = s
		}
	}
}

// WithClock injects a deterministic clock.
func WithClock(now func() time.Time) Option {
	return func(c *Collector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewCollector creates an IAM role collector with safe defaults.
func NewCollector(client IAMAPI, opts ...Option) *Collector {
	c := &Collector{
		client:   client,
		pageSize: defaultPageSize,
		maxPages: defaultMaxPages,
		retry: RetryPolicy{
			MaxRetries: defaultRetryCount,
			BaseDelay:  defaultBaseDelay,
			MaxDelay:   defaultMaxDelay,
		},
		sleep: defaultSleeper,
		now:   time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Collect pulls IAM role assets from AWS and deduplicates results by role ARN.
func (c *Collector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	if c.client == nil {
		return nil, errors.New("collector requires IAM client")
	}

	assets := make([]providers.RawAsset, 0, c.pageSize)
	seen := map[string]struct{}{}
	nextToken := ""

	for page := 1; ; page++ {
		if page > c.maxPages {
			return nil, fmt.Errorf("iam list roles exceeded max pages (%d)", c.maxPages)
		}

		response, err := c.withRetry(ctx, func(callCtx context.Context) (ListRolesPage, error) {
			return c.client.ListRoles(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			return nil, fmt.Errorf("list roles page %d: %w", page, err)
		}

		for _, role := range response.Roles {
			sourceID := strings.TrimSpace(role.ARN)
			if sourceID == "" {
				// ARN is the stable identifier across scans and accounts; skip invalid rows.
				continue
			}
			if _, exists := seen[sourceID]; exists {
				continue
			}

			payload, err := json.Marshal(role)
			if err != nil {
				return nil, fmt.Errorf("marshal role %q: %w", sourceID, err)
			}

			assets = append(assets, providers.RawAsset{
				Kind:      "iam_role",
				SourceID:  sourceID,
				Payload:   payload,
				Collected: c.now().UTC().Format(time.RFC3339Nano),
			})
			seen[sourceID] = struct{}{}
		}

		if response.NextToken == "" {
			break
		}
		nextToken = response.NextToken
	}

	return assets, nil
}

func (c *Collector) withRetry(ctx context.Context, fn func(context.Context) (ListRolesPage, error)) (ListRolesPage, error) {
	var lastErr error
	for attempt := 0; attempt <= c.retry.MaxRetries; attempt++ {
		if ctx.Err() != nil {
			return ListRolesPage{}, ctx.Err()
		}

		result, err := fn(ctx)
		if err == nil {
			return result, nil
		}
		if !isRetryable(err) || attempt == c.retry.MaxRetries {
			lastErr = err
			break
		}

		delay := c.backoff(attempt)
		if sleepErr := c.sleep(ctx, delay); sleepErr != nil {
			return ListRolesPage{}, sleepErr
		}
		lastErr = err
	}
	return ListRolesPage{}, fmt.Errorf("retries exhausted: %w", lastErr)
}

func (c *Collector) backoff(attempt int) time.Duration {
	delay := c.retry.BaseDelay << attempt
	if delay > c.retry.MaxDelay {
		return c.retry.MaxDelay
	}
	return delay
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var retryable RetryableError
	if errors.As(err, &retryable) {
		return retryable.Retryable()
	}

	message := strings.ToLower(err.Error())
	for _, needle := range []string{"throttl", "rate exceeded", "too many requests", "requestlimitexceeded"} {
		if strings.Contains(message, needle) {
			return true
		}
	}
	return false
}

func defaultSleeper(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
