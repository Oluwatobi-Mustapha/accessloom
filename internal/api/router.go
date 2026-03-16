package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const (
	defaultFindingsLimit = 100
	defaultScansLimit    = 20
	maxListLimit         = 500
	scanRequestTimeout   = 2 * time.Minute
	scopeWrite           = "write"
	scopeAdmin           = "admin"
)

// RouterOptions controls API middleware behavior.
type RouterOptions struct {
	APIKeys        []string
	WriteAPIKeys   []string
	APIKeyScopes   map[string][]string
	RateLimitRPM   int
	RateLimitBurst int
	AuditSink      AuditSink
}

// NewRouter builds the REST surface area and observability endpoints.
func NewRouter(logger *zap.Logger, metrics *telemetry.Metrics, svc *Service, opts RouterOptions) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(securityHeadersMiddleware())

	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.ScanRunsTotal, metrics.ScanDurationMS, metrics.FindingsGenerated)

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "identrail",
		})
	})

	r.GET("/metrics", gin.WrapH(promhttp.HandlerFor(registry, promhttp.HandlerOpts{})))

	v1 := r.Group("/v1")
	v1.Use(apiKeyAuthMiddleware(opts.APIKeys, opts.APIKeyScopes))
	v1.Use(rateLimitMiddleware(opts.RateLimitRPM, opts.RateLimitBurst))
	v1.Use(auditLogMiddleware(logger, opts.AuditSink))

	if svc == nil {
		v1.GET("/findings", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/scans", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.POST("/scans", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		return r
	}

	v1.GET("/findings", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		items, err := svc.ListFindings(c.Request.Context(), limit)
		if err != nil {
			logger.Error("list findings", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list findings"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	})

	v1.GET("/scans", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultScansLimit, maxListLimit)
		items, err := svc.ListScans(c.Request.Context(), limit)
		if err != nil {
			logger.Error("list scans", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list scans"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	})

	v1.POST("/scans", requireWriteKeyMiddleware(opts.WriteAPIKeys, opts.APIKeyScopes), func(c *gin.Context) {
		start := time.Now()
		metrics.ScanRunsTotal.Inc()

		requestCtx, cancel := context.WithTimeout(c.Request.Context(), scanRequestTimeout)
		defer cancel()

		result, err := svc.RunScan(requestCtx)
		if err != nil {
			if errors.Is(err, ErrScanInProgress) {
				c.JSON(http.StatusConflict, gin.H{"error": "scan already in progress"})
				return
			}
			logger.Error("run scan", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to run scan"})
			return
		}

		metrics.FindingsGenerated.Add(float64(result.FindingCount))
		metrics.ScanDurationMS.Observe(float64(time.Since(start).Milliseconds()))
		c.JSON(http.StatusAccepted, gin.H{
			"scan":          result.Scan,
			"assets":        result.Assets,
			"finding_count": result.FindingCount,
		})
	})

	return r
}

func parseLimit(raw string, fallback int, max int) int {
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return fallback
	}
	if max > 0 && parsed > max {
		return max
	}
	return parsed
}

func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		c.Next()
	}
}

func apiKeyAuthMiddleware(keys []string, scopedKeys map[string][]string) gin.HandlerFunc {
	if len(scopedKeys) > 0 {
		allowed := map[string]scopeSet{}
		for key, scopes := range scopedKeys {
			trimmed := strings.TrimSpace(key)
			if trimmed == "" {
				continue
			}
			allowed[trimmed] = newScopeSet(scopes)
		}
		if len(allowed) == 0 {
			return func(c *gin.Context) { c.Next() }
		}
		return func(c *gin.Context) {
			candidate := readAPIKey(c)
			scopeSet, ok := allowed[candidate]
			if !ok {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}
			c.Set("auth.api_key", candidate)
			c.Set("auth.scope_set", scopeSet)
			c.Next()
		}
	}

	allowed := map[string]struct{}{}
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		allowed[trimmed] = struct{}{}
	}
	if len(allowed) == 0 {
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		candidate := readAPIKey(c)
		if _, ok := allowed[candidate]; !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set("auth.api_key", candidate)
		c.Next()
	}
}

func requireWriteKeyMiddleware(writeKeys []string, scopedKeys map[string][]string) gin.HandlerFunc {
	if len(scopedKeys) > 0 {
		return func(c *gin.Context) {
			scopeSetValue, exists := c.Get("auth.scope_set")
			if !exists {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
				return
			}
			scopes, ok := scopeSetValue.(scopeSet)
			if !ok || !scopes.has(scopeWrite) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
				return
			}
			c.Next()
		}
	}

	allowed := map[string]struct{}{}
	for _, key := range writeKeys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		allowed[trimmed] = struct{}{}
	}
	if len(allowed) == 0 {
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		apiKeyValue, exists := c.Get("auth.api_key")
		if !exists {
			// If API key auth is disabled, write authorization cannot be enforced.
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		apiKey, _ := apiKeyValue.(string)
		if _, ok := allowed[apiKey]; !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

type ipRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
}

func newIPRateLimiter(rpm int, burst int) *ipRateLimiter {
	if rpm <= 0 {
		rpm = 120
	}
	if burst <= 0 {
		burst = 20
	}
	return &ipRateLimiter{
		limiters: map[string]*rate.Limiter{},
		rate:     rate.Every(time.Minute / time.Duration(rpm)),
		burst:    burst,
	}
}

func (l *ipRateLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	limiter, ok := l.limiters[ip]
	if !ok {
		limiter = rate.NewLimiter(l.rate, l.burst)
		l.limiters[ip] = limiter
	}
	return limiter.Allow()
}

func rateLimitMiddleware(rpm int, burst int) gin.HandlerFunc {
	limiter := newIPRateLimiter(rpm, burst)
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if ip == "" {
			ip = "unknown"
		}
		if !limiter.allow(ip) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}

func auditLogMiddleware(logger *zap.Logger, sink AuditSink) gin.HandlerFunc {
	if sink == nil {
		sink = NopAuditSink{}
	}
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		event := AuditEvent{
			Timestamp:  time.Now().UTC(),
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			Status:     c.Writer.Status(),
			ClientIP:   c.ClientIP(),
			DurationMS: time.Since(start).Milliseconds(),
			UserAgent:  c.Request.UserAgent(),
		}
		if apiKeyValue, exists := c.Get("auth.api_key"); exists {
			if apiKey, ok := apiKeyValue.(string); ok {
				event.APIKey = apiKey
			}
		}
		logger.Info(
			"api request",
			zap.String("method", event.Method),
			zap.String("path", event.Path),
			zap.Int("status", event.Status),
			zap.String("client_ip", event.ClientIP),
			zap.Int64("duration_ms", event.DurationMS),
			zap.String("user_agent", event.UserAgent),
		)
		if err := sink.Write(event); err != nil {
			logger.Warn("audit sink write failed", telemetry.ZapError(err))
		}
	}
}

func readAPIKey(c *gin.Context) string {
	candidate := strings.TrimSpace(c.GetHeader("X-API-Key"))
	if candidate != "" {
		return candidate
	}
	authz := strings.TrimSpace(c.GetHeader("Authorization"))
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	return ""
}

type scopeSet map[string]struct{}

func newScopeSet(scopes []string) scopeSet {
	set := scopeSet{}
	for _, raw := range scopes {
		normalized := strings.ToLower(strings.TrimSpace(raw))
		if normalized == "" {
			continue
		}
		set[normalized] = struct{}{}
	}
	return set
}

func (s scopeSet) has(required string) bool {
	if len(s) == 0 {
		return false
	}
	if _, ok := s[scopeAdmin]; ok {
		return true
	}
	_, ok := s[required]
	return ok
}
