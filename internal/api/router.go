package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const (
	defaultFindingsLimit   = 100
	defaultScansLimit      = 20
	defaultEventsLimit     = 100
	maxListLimit           = 500
	maxCursorFetchLimit    = 5000
	rateLimiterEntryTTL    = 15 * time.Minute
	rateLimiterMaxEntries  = 10000
	rateLimiterCleanupTick = 256
	corsAllowMethods       = "GET,POST,PATCH,OPTIONS"
	corsAllowHeaders       = "Authorization,Content-Type,X-API-Key,X-Identrail-Tenant-ID,X-Identrail-Workspace-ID"
	corsMaxAgeSeconds      = "600"
	scopeRead              = "read"
	scopeWrite             = "write"
	scopeAdmin             = "admin"
	scopeHeaderTenantID    = "X-Identrail-Tenant-ID"
	scopeHeaderWorkspaceID = "X-Identrail-Workspace-ID"
)

// RouterOptions controls API middleware behavior.
type RouterOptions struct {
	APIKeys            []string
	WriteAPIKeys       []string
	APIKeyScopes       map[string][]string
	OIDCTokenVerifier  TokenVerifier
	OIDCWriteScopes    []string
	RateLimitRPM       int
	RateLimitBurst     int
	AuditSink          AuditSink
	TrustedProxies     []string
	CORSAllowedOrigins []string
	DefaultTenantID    string
	DefaultWorkspaceID string
}

// VerifiedToken contains normalized claims extracted from a validated OIDC token.
type VerifiedToken struct {
	Subject     string
	Issuer      string
	Audiences   []string
	TenantID    string
	WorkspaceID string
	Groups      []string
	Roles       []string
	Scopes      []string
}

// TokenVerifier validates bearer tokens and returns normalized claims.
type TokenVerifier interface {
	VerifyToken(ctx context.Context, rawToken string) (VerifiedToken, error)
}

// NewRouter builds the REST surface area and observability endpoints.
func NewRouter(logger *zap.Logger, metrics *telemetry.Metrics, svc *Service, opts RouterOptions) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	configureTrustedProxies(r, logger, opts.TrustedProxies)
	r.Use(gin.Recovery())
	r.Use(securityHeadersMiddleware())
	r.Use(corsMiddleware(opts.CORSAllowedOrigins))

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		metrics.ScanRunsTotal,
		metrics.ScanSuccessTotal,
		metrics.ScanFailureTotal,
		metrics.ScanPartialTotal,
		metrics.ScanInFlight,
		metrics.ScanDurationMS,
		metrics.FindingsGenerated,
		metrics.RepoScanRunsTotal,
		metrics.RepoScanFailureTotal,
		metrics.RepoScanDurationMS,
	)

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "identrail",
		})
	})

	r.GET("/metrics", gin.WrapH(promhttp.HandlerFor(registry, promhttp.HandlerOpts{})))

	var authzStore db.Store
	if svc != nil {
		authzStore = svc.Store
	}

	v1 := r.Group("/v1")
	v1.Use(apiKeyAuthMiddleware(opts.APIKeys, opts.APIKeyScopes, opts.OIDCTokenVerifier, opts.OIDCWriteScopes))
	v1.Use(requestScopeMiddleware(opts.DefaultTenantID, opts.DefaultWorkspaceID))
	v1.Use(requireCentralPolicyMiddleware(newCentralPolicyRuntimeResolver(authzStore), opts.WriteAPIKeys, opts.APIKeyScopes, authzStore))
	v1.Use(rateLimitMiddleware(opts.RateLimitRPM, opts.RateLimitBurst))
	v1.Use(auditLogMiddleware(logger, opts.AuditSink))

	if svc == nil {
		v1.GET("/findings", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/findings/:finding_id", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		v1.GET("/findings/:finding_id/history", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/findings/:finding_id/exports", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		v1.GET("/findings/trends", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/findings/summary", func(c *gin.Context) {
			c.JSON(http.StatusOK, FindingsSummary{
				Total:      0,
				BySeverity: map[string]int{},
				ByType:     map[string]int{},
			})
		})
		v1.GET("/identities", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/relationships", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/ownership/signals", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/scans", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/scans/:scan_id/diff", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		v1.GET("/scans/:scan_id/events", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/repo-scans", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.GET("/repo-scans/:repo_scan_id", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "repo scan service unavailable"})
		})
		v1.GET("/repo-findings", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		v1.POST("/scans", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		v1.PATCH("/findings/:finding_id/triage", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		v1.POST("/repo-scans", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "repo scan service unavailable"})
		})
		return r
	}

	v1.GET("/findings", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "created_at")
		items, err := svc.ListFindingsFiltered(c.Request.Context(), pageFetchLimit(offset, limit), FindingsFilter{
			ScanID:          strings.TrimSpace(c.Query("scan_id")),
			Severity:        strings.TrimSpace(c.Query("severity")),
			Type:            strings.TrimSpace(c.Query("type")),
			LifecycleStatus: strings.TrimSpace(c.Query("lifecycle_status")),
			Assignee:        strings.TrimSpace(c.Query("assignee")),
		})
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
				return
			}
			logger.Error("list findings", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list findings"})
			return
		}
		sortFindings(items, sortBy, sortDesc)
		page, next := pageWithCursor(items, offset, limit)
		response := gin.H{"items": page}
		if next != "" {
			response["next_cursor"] = next
		}
		c.JSON(http.StatusOK, response)
	})

	v1.GET("/findings/summary", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		summary, err := svc.GetFindingsSummary(c.Request.Context(), limit)
		if err != nil {
			logger.Error("findings summary", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build findings summary"})
			return
		}
		c.JSON(http.StatusOK, summary)
	})

	v1.GET("/findings/:finding_id", func(c *gin.Context) {
		item, err := svc.GetFinding(
			c.Request.Context(),
			strings.TrimSpace(c.Param("finding_id")),
			strings.TrimSpace(c.Query("scan_id")),
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
				return
			}
			logger.Error("get finding", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get finding"})
			return
		}
		c.JSON(http.StatusOK, item)
	})

	v1.GET("/findings/:finding_id/history", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultEventsLimit, maxListLimit)
		items, err := svc.ListFindingTriageHistory(
			c.Request.Context(),
			strings.TrimSpace(c.Param("finding_id")),
			strings.TrimSpace(c.Query("scan_id")),
			limit,
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
				return
			}
			logger.Error("list finding history", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list finding history"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	})

	v1.GET("/findings/:finding_id/exports", func(c *gin.Context) {
		exports, err := svc.GetFindingExports(
			c.Request.Context(),
			strings.TrimSpace(c.Param("finding_id")),
			strings.TrimSpace(c.Query("scan_id")),
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
				return
			}
			logger.Error("get finding exports", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to export finding"})
			return
		}
		c.JSON(http.StatusOK, exports)
	})

	v1.GET("/findings/trends", func(c *gin.Context) {
		points := parseLimit(c.Query("points"), 10, 100)
		items, err := svc.GetFindingsTrendFiltered(
			c.Request.Context(),
			points,
			strings.TrimSpace(c.Query("severity")),
			strings.TrimSpace(c.Query("type")),
		)
		if err != nil {
			logger.Error("findings trends", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build findings trends"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	})

	v1.PATCH("/findings/:finding_id/triage", func(c *gin.Context) {
		var request FindingTriageRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		item, err := svc.TriageFinding(
			c.Request.Context(),
			strings.TrimSpace(c.Param("finding_id")),
			strings.TrimSpace(c.Query("scan_id")),
			request,
			triageActorFromContext(c),
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
				return
			}
			if errors.Is(err, ErrInvalidFindingTriageRequest) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid triage request"})
				return
			}
			logger.Error("triage finding", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to triage finding"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"finding": item})
	})

	v1.GET("/identities", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "name")
		items, err := svc.ListIdentities(
			c.Request.Context(),
			strings.TrimSpace(c.Query("scan_id")),
			strings.TrimSpace(c.Query("provider")),
			strings.TrimSpace(c.Query("type")),
			strings.TrimSpace(c.Query("name_prefix")),
			pageFetchLimit(offset, limit),
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
				return
			}
			logger.Error("list identities", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list identities"})
			return
		}
		sortIdentities(items, sortBy, sortDesc)
		page, next := pageWithCursor(items, offset, limit)
		response := gin.H{"items": page}
		if next != "" {
			response["next_cursor"] = next
		}
		c.JSON(http.StatusOK, response)
	})

	v1.GET("/relationships", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "discovered_at")
		items, err := svc.ListRelationships(
			c.Request.Context(),
			strings.TrimSpace(c.Query("scan_id")),
			strings.TrimSpace(c.Query("type")),
			strings.TrimSpace(c.Query("from_node_id")),
			strings.TrimSpace(c.Query("to_node_id")),
			pageFetchLimit(offset, limit),
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
				return
			}
			logger.Error("list relationships", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list relationships"})
			return
		}
		sortRelationships(items, sortBy, sortDesc)
		page, next := pageWithCursor(items, offset, limit)
		response := gin.H{"items": page}
		if next != "" {
			response["next_cursor"] = next
		}
		c.JSON(http.StatusOK, response)
	})

	v1.GET("/ownership/signals", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "confidence")
		items, err := svc.ListOwnershipSignals(
			c.Request.Context(),
			pageFetchLimit(offset, limit),
			OwnershipFilter{ScanID: strings.TrimSpace(c.Query("scan_id"))},
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
				return
			}
			logger.Error("list ownership signals", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list ownership signals"})
			return
		}
		sortOwnershipSignals(items, sortBy, sortDesc)
		page, next := pageWithCursor(items, offset, limit)
		response := gin.H{"items": page}
		if next != "" {
			response["next_cursor"] = next
		}
		c.JSON(http.StatusOK, response)
	})

	v1.GET("/scans", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultScansLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "started_at")
		items, err := svc.ListScans(c.Request.Context(), pageFetchLimit(offset, limit))
		if err != nil {
			logger.Error("list scans", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list scans"})
			return
		}
		sortScans(items, sortBy, sortDesc)
		page, next := pageWithCursor(items, offset, limit)
		response := gin.H{"items": page}
		if next != "" {
			response["next_cursor"] = next
		}
		c.JSON(http.StatusOK, response)
	})

	v1.GET("/scans/:scan_id/diff", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		diff, err := svc.GetScanDiffAgainst(
			c.Request.Context(),
			strings.TrimSpace(c.Param("scan_id")),
			strings.TrimSpace(c.Query("previous_scan_id")),
			limit,
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
				return
			}
			if errors.Is(err, ErrInvalidScanDiffBaseline) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid previous_scan_id"})
				return
			}
			logger.Error("scan diff", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build scan diff"})
			return
		}
		c.JSON(http.StatusOK, diff)
	})

	v1.GET("/scans/:scan_id/events", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultEventsLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "created_at")
		items, err := svc.ListScanEventsFiltered(
			c.Request.Context(),
			strings.TrimSpace(c.Param("scan_id")),
			strings.TrimSpace(c.Query("level")),
			pageFetchLimit(offset, limit),
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
				return
			}
			logger.Error("scan events", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list scan events"})
			return
		}
		sortScanEvents(items, sortBy, sortDesc)
		page, next := pageWithCursor(items, offset, limit)
		response := gin.H{"items": page}
		if next != "" {
			response["next_cursor"] = next
		}
		c.JSON(http.StatusOK, response)
	})

	v1.GET("/repo-scans", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultScansLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "started_at")
		items, err := svc.ListRepoScans(c.Request.Context(), pageFetchLimit(offset, limit))
		if err != nil {
			logger.Error("list repo scans", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list repo scans"})
			return
		}
		sortRepoScans(items, sortBy, sortDesc)
		page, next := pageWithCursor(items, offset, limit)
		response := gin.H{"items": page}
		if next != "" {
			response["next_cursor"] = next
		}
		c.JSON(http.StatusOK, response)
	})

	v1.GET("/repo-scans/:repo_scan_id", func(c *gin.Context) {
		repoScanID := strings.TrimSpace(c.Param("repo_scan_id"))
		if !isValidUUID(repoScanID) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid repo_scan_id"})
			return
		}
		item, err := svc.GetRepoScan(c.Request.Context(), repoScanID)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "repo scan not found"})
				return
			}
			logger.Error("get repo scan", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get repo scan"})
			return
		}
		c.JSON(http.StatusOK, item)
	})

	v1.GET("/repo-findings", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		offset := parseCursor(c.Query("cursor"))
		sortBy, sortDesc := parseSortParams(c.Query("sort_by"), c.Query("sort_order"), "created_at")
		repoScanID := strings.TrimSpace(c.Query("repo_scan_id"))
		if repoScanID != "" && !isValidUUID(repoScanID) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid repo_scan_id"})
			return
		}
		items, err := svc.ListRepoFindings(
			c.Request.Context(),
			pageFetchLimit(offset, limit),
			db.RepoFindingFilter{
				RepoScanID: repoScanID,
				Severity:   strings.TrimSpace(c.Query("severity")),
				Type:       strings.TrimSpace(c.Query("type")),
			},
		)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "repo scan not found"})
				return
			}
			logger.Error("list repo findings", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list repo findings"})
			return
		}
		sortFindings(items, sortBy, sortDesc)
		page, next := pageWithCursor(items, offset, limit)
		response := gin.H{"items": page}
		if next != "" {
			response["next_cursor"] = next
		}
		c.JSON(http.StatusOK, response)
	})

	v1.POST("/scans", func(c *gin.Context) {
		start := time.Now()
		metrics.ScanRunsTotal.Inc()
		metrics.ScanInFlight.Inc()
		defer metrics.ScanInFlight.Dec()
		defer func() {
			metrics.ScanDurationMS.Observe(float64(time.Since(start).Milliseconds()))
		}()

		scan, err := svc.EnqueueScan(c.Request.Context())
		if err != nil {
			metrics.ScanFailureTotal.Inc()
			if errors.Is(err, ErrScanQueueFull) {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "scan queue is full"})
				return
			}
			logger.Error("enqueue scan", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enqueue scan"})
			return
		}

		c.JSON(http.StatusAccepted, gin.H{
			"scan": scan,
		})
	})

	v1.POST("/repo-scans", func(c *gin.Context) {
		start := time.Now()
		metrics.RepoScanRunsTotal.Inc()
		defer func() {
			metrics.RepoScanDurationMS.Observe(float64(time.Since(start).Milliseconds()))
		}()

		var request RepoScanRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			metrics.RepoScanFailureTotal.Inc()
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		record, err := svc.EnqueueRepoScan(c.Request.Context(), request)
		if err != nil {
			metrics.RepoScanFailureTotal.Inc()
			if errors.Is(err, ErrInvalidRepoScanRequest) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid repo scan request"})
				return
			}
			if errors.Is(err, ErrRepoScanInProgress) {
				c.JSON(http.StatusConflict, gin.H{"error": "repo scan already in progress"})
				return
			}
			if errors.Is(err, ErrRepoTargetNotAllowed) {
				c.JSON(http.StatusForbidden, gin.H{"error": "repo target not allowed"})
				return
			}
			if errors.Is(err, ErrRepoScanDisabled) {
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "repo scan is disabled"})
				return
			}
			if errors.Is(err, ErrRepoScanQueueFull) {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "repo scan queue is full"})
				return
			}
			logger.Error("enqueue repo scan", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enqueue repo scan"})
			return
		}

		c.JSON(http.StatusAccepted, gin.H{
			"repo_scan": record,
		})
	})

	return r
}

func configureTrustedProxies(r *gin.Engine, logger *zap.Logger, proxies []string) {
	normalized := normalizeTrustedProxies(proxies)
	var err error
	if len(normalized) == 0 {
		err = r.SetTrustedProxies(nil)
	} else {
		err = r.SetTrustedProxies(normalized)
	}
	if err != nil {
		if logger != nil {
			logger.Warn("invalid trusted proxy configuration; disabling proxy trust", telemetry.ZapError(err))
		}
		_ = r.SetTrustedProxies(nil)
	}
}

func normalizeTrustedProxies(proxies []string) []string {
	if len(proxies) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(proxies))
	normalized := make([]string, 0, len(proxies))
	for _, item := range proxies {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
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

func parseCursor(raw string) int {
	if strings.TrimSpace(raw) == "" {
		return 0
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}

func parseSortParams(rawBy string, rawOrder string, fallbackBy string) (string, bool) {
	by := strings.ToLower(strings.TrimSpace(rawBy))
	if by == "" {
		by = fallbackBy
	}
	order := strings.ToLower(strings.TrimSpace(rawOrder))
	if order == "asc" {
		return by, false
	}
	return by, true
}

func isValidUUID(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return false
	}
	_, err := uuid.Parse(strings.TrimSpace(raw))
	return err == nil
}

func sortFindings(items []domain.Finding, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "severity":
			cmp = compareInt(severityOrder(left.Severity), severityOrder(right.Severity))
		case "type":
			cmp = compareString(string(left.Type), string(right.Type))
		case "title":
			cmp = compareString(left.Title, right.Title)
		default:
			cmp = compareTime(left.CreatedAt, right.CreatedAt)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortScans(items []db.ScanRecord, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "finding_count":
			cmp = compareInt(left.FindingCount, right.FindingCount)
		case "asset_count":
			cmp = compareInt(left.AssetCount, right.AssetCount)
		case "status":
			cmp = compareString(left.Status, right.Status)
		default:
			cmp = compareTime(left.StartedAt, right.StartedAt)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortScanEvents(items []db.ScanEvent, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "level":
			cmp = compareInt(scanEventLevelRank(left.Level), scanEventLevelRank(right.Level))
		case "message":
			cmp = compareString(left.Message, right.Message)
		default:
			cmp = compareTime(left.CreatedAt, right.CreatedAt)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortRepoScans(items []db.RepoScanRecord, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "finding_count":
			cmp = compareInt(left.FindingCount, right.FindingCount)
		case "commits_scanned":
			cmp = compareInt(left.CommitsScanned, right.CommitsScanned)
		case "repository":
			cmp = compareString(left.Repository, right.Repository)
		case "status":
			cmp = compareString(left.Status, right.Status)
		default:
			cmp = compareTime(left.StartedAt, right.StartedAt)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortIdentities(items []domain.Identity, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "type":
			cmp = compareString(string(left.Type), string(right.Type))
		case "provider":
			cmp = compareString(string(left.Provider), string(right.Provider))
		case "created_at":
			cmp = compareTime(left.CreatedAt, right.CreatedAt)
		default:
			cmp = compareString(left.Name, right.Name)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortRelationships(items []domain.Relationship, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "type":
			cmp = compareString(string(left.Type), string(right.Type))
		case "from_node_id":
			cmp = compareString(left.FromNodeID, right.FromNodeID)
		case "to_node_id":
			cmp = compareString(left.ToNodeID, right.ToNodeID)
		default:
			cmp = compareTime(left.DiscoveredAt, right.DiscoveredAt)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func sortOwnershipSignals(items []domain.OwnershipSignal, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "team":
			cmp = compareString(left.Team, right.Team)
		case "source":
			cmp = compareString(left.Source, right.Source)
		default:
			cmp = compareFloat(left.Confidence, right.Confidence)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func compareTime(left time.Time, right time.Time) int {
	switch {
	case left.Before(right):
		return -1
	case left.After(right):
		return 1
	default:
		return 0
	}
}

func compareString(left string, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func compareInt(left int, right int) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func compareFloat(left float64, right float64) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func severityOrder(severity domain.FindingSeverity) int {
	switch severity {
	case domain.SeverityCritical:
		return 5
	case domain.SeverityHigh:
		return 4
	case domain.SeverityMedium:
		return 3
	case domain.SeverityLow:
		return 2
	case domain.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func scanEventLevelRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case db.ScanEventLevelError:
		return 4
	case db.ScanEventLevelWarn:
		return 3
	case db.ScanEventLevelInfo:
		return 2
	case db.ScanEventLevelDebug:
		return 1
	default:
		return 0
	}
}

func pageFetchLimit(offset int, limit int) int {
	if limit <= 0 {
		limit = defaultFindingsLimit
	}
	fetch := offset + limit + 1
	if fetch > maxCursorFetchLimit {
		return maxCursorFetchLimit
	}
	return fetch
}

func pageWithCursor[T any](items []T, offset int, limit int) ([]T, string) {
	if limit <= 0 {
		limit = defaultFindingsLimit
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= len(items) {
		return []T{}, ""
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	next := ""
	if end < len(items) {
		next = strconv.Itoa(end)
	}
	return items[offset:end], next
}

func requestScopeMiddleware(defaultTenantID string, defaultWorkspaceID string) gin.HandlerFunc {
	defaultScope := db.Scope{
		TenantID:    defaultTenantID,
		WorkspaceID: defaultWorkspaceID,
	}.Normalize()
	return func(c *gin.Context) {
		tenantID := authContextString(c, "auth.tenant_id")
		if tenantID == "" {
			tenantID = strings.TrimSpace(c.GetHeader(scopeHeaderTenantID))
		}
		if tenantID == "" {
			tenantID = defaultScope.TenantID
		}
		workspaceID := authContextString(c, "auth.workspace_id")
		if workspaceID == "" {
			workspaceID = strings.TrimSpace(c.GetHeader(scopeHeaderWorkspaceID))
		}
		if workspaceID == "" {
			workspaceID = defaultScope.WorkspaceID
		}
		scopedCtx := db.WithScope(c.Request.Context(), db.Scope{
			TenantID:    tenantID,
			WorkspaceID: workspaceID,
		})
		c.Request = c.Request.WithContext(scopedCtx)
		c.Next()
	}
}

func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	allowAll := false
	allowed := map[string]struct{}{}
	for _, origin := range allowedOrigins {
		trimmed := strings.TrimSpace(origin)
		if trimmed == "" {
			continue
		}
		if trimmed == "*" {
			allowAll = true
			continue
		}
		allowed[trimmed] = struct{}{}
	}

	if !allowAll && len(allowed) == 0 {
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		origin := strings.TrimSpace(c.GetHeader("Origin"))
		if origin == "" {
			c.Next()
			return
		}

		allowedOrigin := ""
		if allowAll {
			allowedOrigin = "*"
		} else if _, ok := allowed[origin]; ok {
			allowedOrigin = origin
		}
		if allowedOrigin == "" {
			c.Next()
			return
		}

		addVaryHeader(c.Writer.Header(), "Origin")
		c.Header("Access-Control-Allow-Origin", allowedOrigin)
		c.Header("Access-Control-Allow-Methods", corsAllowMethods)
		c.Header("Access-Control-Allow-Headers", corsAllowHeaders)
		c.Header("Access-Control-Max-Age", corsMaxAgeSeconds)

		if c.Request.Method == http.MethodOptions && strings.TrimSpace(c.GetHeader("Access-Control-Request-Method")) != "" {
			addVaryHeader(c.Writer.Header(), "Access-Control-Request-Method")
			addVaryHeader(c.Writer.Header(), "Access-Control-Request-Headers")
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func addVaryHeader(headers http.Header, value string) {
	if headers == nil {
		return
	}
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return
	}
	for _, existing := range strings.Split(headers.Get("Vary"), ",") {
		if strings.EqualFold(strings.TrimSpace(existing), normalized) {
			return
		}
	}
	current := strings.TrimSpace(headers.Get("Vary"))
	if current == "" {
		headers.Set("Vary", normalized)
		return
	}
	headers.Set("Vary", current+", "+normalized)
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

func apiKeyAuthMiddleware(keys []string, scopedKeys map[string][]string, tokenVerifier TokenVerifier, oidcWriteScopes []string) gin.HandlerFunc {
	oidcWriteScopeSet := newScopeSet(oidcWriteScopes)

	scopedAllowed := map[string]scopeSet{}
	for key, scopes := range scopedKeys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		scopedAllowed[trimmed] = newScopeSet(scopes)
	}

	// Scoped keys are the source of truth when configured.
	legacyAllowed := []string{}
	if len(scopedAllowed) == 0 {
		for _, key := range keys {
			trimmed := strings.TrimSpace(key)
			if trimmed == "" {
				continue
			}
			legacyAllowed = append(legacyAllowed, trimmed)
		}
	}

	if len(scopedAllowed) == 0 && len(legacyAllowed) == 0 && tokenVerifier == nil {
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		if candidate := readAPIKey(c); candidate != "" {
			if scopes, ok := scopedKeyLookup(scopedAllowed, candidate); ok {
				c.Set("auth.api_key", candidate)
				c.Set("auth.scope_set", scopes)
				c.Next()
				return
			}
			if keyInList(legacyAllowed, candidate) {
				c.Set("auth.api_key", candidate)
				c.Next()
				return
			}
		}

		rawBearer := readBearerToken(c)
		if tokenVerifier != nil && rawBearer != "" {
			token, err := tokenVerifier.VerifyToken(c.Request.Context(), rawBearer)
			if err == nil {
				c.Set("auth.subject", token.Subject)
				c.Set("auth.issuer", token.Issuer)
				c.Set("auth.audiences", token.Audiences)
				c.Set("auth.groups", token.Groups)
				c.Set("auth.roles", token.Roles)
				c.Set("auth.tenant_id", token.TenantID)
				c.Set("auth.workspace_id", token.WorkspaceID)
				c.Set("auth.scope_set", scopeSetFromOIDCToken(token, oidcWriteScopeSet))
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}
}

func keyInList(keys []string, candidate string) bool {
	for _, key := range keys {
		if secureKeyEquals(key, candidate) {
			return true
		}
	}
	return false
}

func scopedKeyLookup(scoped map[string]scopeSet, candidate string) (scopeSet, bool) {
	for key, scopes := range scoped {
		if secureKeyEquals(key, candidate) {
			return scopes, true
		}
	}
	return scopeSet{}, false
}

func secureKeyEquals(expected string, candidate string) bool {
	if len(expected) != len(candidate) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(candidate)) == 1
}

type ipRateLimiter struct {
	mu           sync.Mutex
	limiters     map[string]ipLimiterEntry
	rate         rate.Limit
	burst        int
	now          func() time.Time
	entryTTL     time.Duration
	maxEntries   int
	cleanupEvery uint64
	allowCount   uint64
}

type ipLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter(rpm int, burst int) *ipRateLimiter {
	return newIPRateLimiterWithClock(rpm, burst, time.Now, rateLimiterEntryTTL, rateLimiterMaxEntries, rateLimiterCleanupTick)
}

func newIPRateLimiterWithClock(
	rpm int,
	burst int,
	now func() time.Time,
	entryTTL time.Duration,
	maxEntries int,
	cleanupEvery uint64,
) *ipRateLimiter {
	if rpm <= 0 {
		rpm = 120
	}
	if burst <= 0 {
		burst = 20
	}
	if now == nil {
		now = time.Now
	}
	if entryTTL <= 0 {
		entryTTL = rateLimiterEntryTTL
	}
	if maxEntries <= 0 {
		maxEntries = rateLimiterMaxEntries
	}
	if cleanupEvery == 0 {
		cleanupEvery = rateLimiterCleanupTick
	}
	return &ipRateLimiter{
		limiters:     map[string]ipLimiterEntry{},
		rate:         rate.Every(time.Minute / time.Duration(rpm)),
		burst:        burst,
		now:          now,
		entryTTL:     entryTTL,
		maxEntries:   maxEntries,
		cleanupEvery: cleanupEvery,
	}
}

func (l *ipRateLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.allowCount++
	if l.cleanupEvery > 0 && l.allowCount%l.cleanupEvery == 0 {
		l.evictExpiredLocked(now)
	}

	entry, ok := l.limiters[ip]
	if !ok {
		if len(l.limiters) >= l.maxEntries {
			l.evictExpiredLocked(now)
		}
		if len(l.limiters) >= l.maxEntries {
			l.evictOldestLocked()
		}
		entry = ipLimiterEntry{
			limiter:  rate.NewLimiter(l.rate, l.burst),
			lastSeen: now,
		}
		l.limiters[ip] = entry
	} else {
		entry.lastSeen = now
		l.limiters[ip] = entry
	}
	return entry.limiter.Allow()
}

func (l *ipRateLimiter) evictExpiredLocked(now time.Time) {
	if len(l.limiters) == 0 {
		return
	}
	cutoff := now.Add(-l.entryTTL)
	for ip, entry := range l.limiters {
		if entry.lastSeen.Before(cutoff) {
			delete(l.limiters, ip)
		}
	}
}

func (l *ipRateLimiter) evictOldestLocked() {
	if len(l.limiters) == 0 {
		return
	}
	var oldestIP string
	var oldestTime time.Time
	for ip, entry := range l.limiters {
		if oldestIP == "" || entry.lastSeen.Before(oldestTime) {
			oldestIP = ip
			oldestTime = entry.lastSeen
		}
	}
	if oldestIP != "" {
		delete(l.limiters, oldestIP)
	}
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
				event.APIKeyID = fingerprintAPIKey(apiKey)
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
	return strings.TrimSpace(c.GetHeader("X-API-Key"))
}

func authContextString(c *gin.Context, key string) string {
	if c == nil {
		return ""
	}
	value, exists := c.Get(key)
	if !exists {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func triageActorFromContext(c *gin.Context) string {
	if c == nil {
		return "unknown"
	}
	if subjectValue, exists := c.Get("auth.subject"); exists {
		if subject, ok := subjectValue.(string); ok {
			normalizedSubject := strings.TrimSpace(subject)
			if normalizedSubject != "" {
				return "subject:" + normalizedSubject
			}
		}
	}
	if apiKeyValue, exists := c.Get("auth.api_key"); exists {
		if apiKey, ok := apiKeyValue.(string); ok {
			normalizedKey := strings.TrimSpace(apiKey)
			if normalizedKey != "" {
				return "api_key:" + fingerprintAPIKey(normalizedKey)
			}
		}
	}
	return "unknown"
}

func readBearerToken(c *gin.Context) string {
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
	if required == scopeRead {
		if _, ok := s[scopeWrite]; ok {
			return true
		}
	}
	_, ok := s[required]
	return ok
}

func scopeSetFromOIDCToken(token VerifiedToken, writeScopeOverrides scopeSet) scopeSet {
	set := scopeSet{}
	for _, scope := range token.Scopes {
		normalized := strings.ToLower(strings.TrimSpace(scope))
		if normalized == "" {
			continue
		}
		switch normalized {
		case scopeAdmin, "identrail.admin":
			set[scopeAdmin] = struct{}{}
			set[scopeWrite] = struct{}{}
			set[scopeRead] = struct{}{}
		case scopeWrite, "identrail.write":
			set[scopeWrite] = struct{}{}
		case scopeRead, "identrail.read":
			set[scopeRead] = struct{}{}
		}
		if _, ok := writeScopeOverrides[normalized]; ok {
			set[scopeWrite] = struct{}{}
		}
	}
	return set
}
