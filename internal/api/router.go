package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

const (
	defaultFindingsLimit = 100
	defaultScansLimit    = 20
	maxListLimit         = 500
	scanRequestTimeout   = 2 * time.Minute
)

// NewRouter builds the REST surface area and observability endpoints.
func NewRouter(logger *zap.Logger, metrics *telemetry.Metrics, svc *Service) *gin.Engine {
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

	if svc == nil {
		r.GET("/v1/findings", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		r.GET("/v1/scans", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []any{}})
		})
		r.POST("/v1/scans", func(c *gin.Context) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan service unavailable"})
		})
		return r
	}

	r.GET("/v1/findings", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultFindingsLimit, maxListLimit)
		items, err := svc.ListFindings(c.Request.Context(), limit)
		if err != nil {
			logger.Error("list findings", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list findings"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	})

	r.GET("/v1/scans", func(c *gin.Context) {
		limit := parseLimit(c.Query("limit"), defaultScansLimit, maxListLimit)
		items, err := svc.ListScans(c.Request.Context(), limit)
		if err != nil {
			logger.Error("list scans", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list scans"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	})

	r.POST("/v1/scans", func(c *gin.Context) {
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
