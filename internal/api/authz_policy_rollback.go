package api

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type authzPolicyRollbackRequest struct {
	PolicySetID   string `json:"policy_set_id"`
	TargetVersion int    `json:"target_version"`
	Actor         string `json:"actor"`
}

type authzPolicyRollbackResponse struct {
	PolicySetID              string    `json:"policy_set_id"`
	PreviousEffective        *int      `json:"previous_effective_version,omitempty"`
	PreviousActiveVersion    *int      `json:"previous_active_version,omitempty"`
	PreviousCandidateVersion *int      `json:"previous_candidate_version,omitempty"`
	ActiveVersion            int       `json:"active_version"`
	RolloutMode              string    `json:"rollout_mode"`
	UpdatedAt                time.Time `json:"updated_at"`
}

func authzPolicyRollbackHandler(logger *zap.Logger, store db.Store, metrics *telemetry.Metrics) gin.HandlerFunc {
	if logger == nil {
		logger = zap.NewNop()
	}
	return func(c *gin.Context) {
		if store == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "policy store unavailable"})
			return
		}

		var request authzPolicyRollbackRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		if request.TargetVersion <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target_version must be greater than zero"})
			return
		}

		policySetID := strings.TrimSpace(request.PolicySetID)
		if policySetID == "" {
			policySetID = defaultCentralPolicySetID
		}

		if err := validateAuthzPolicyVersionBundle(c.Request.Context(), store, policySetID, request.TargetVersion); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "target policy version not found"})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": "target policy version is not valid"})
			return
		}

		rollout, err := store.GetAuthzPolicyRollout(c.Request.Context(), policySetID)
		if err != nil {
			if !errors.Is(err, db.ErrNotFound) {
				logger.Error("read policy rollout before rollback", telemetry.ZapError(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to rollback policy"})
				return
			}
			rollout = db.AuthzPolicyRollout{
				PolicySetID:      policySetID,
				Mode:             db.AuthzPolicyRolloutModeDisabled,
				CanaryPercentage: 100,
			}
		}
		previousEffective := effectiveVersionBeforeRollback(rollout)
		previousActive := cloneIntPointer(rollout.ActiveVersion)
		previousCandidate := cloneIntPointer(rollout.CandidateVersion)

		targetVersion := request.TargetVersion
		updatedAt := time.Now().UTC()
		nextRollout := db.AuthzPolicyRollout{
			PolicySetID:        policySetID,
			ActiveVersion:      &targetVersion,
			CandidateVersion:   nil,
			Mode:               db.AuthzPolicyRolloutModeDisabled,
			TenantAllowlist:    nil,
			WorkspaceAllowlist: nil,
			CanaryPercentage:   100,
			ValidatedVersions:  appendValidatedVersion(rollout.ValidatedVersions, targetVersion),
			UpdatedBy:          effectiveRollbackActor(c, request.Actor),
			UpdatedAt:          updatedAt,
		}
		if err := store.UpsertAuthzPolicyRollout(c.Request.Context(), nextRollout); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "policy set or version not found"})
				return
			}
			logger.Error("upsert rollback policy rollout", telemetry.ZapError(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to rollback policy"})
			return
		}

		if metrics != nil && metrics.AuthzPolicyRollbacksTotal != nil {
			metrics.AuthzPolicyRollbacksTotal.Inc()
		}
		if err := store.AppendAuthzPolicyEvent(c.Request.Context(), db.AuthzPolicyEvent{
			PolicySetID: policySetID,
			EventType:   "rollback",
			FromVersion: previousEffective,
			ToVersion:   &targetVersion,
			Actor:       nextRollout.UpdatedBy,
			Message:     "rolled back active policy version",
			Metadata: map[string]any{
				"previous_active_version":    previousActive,
				"previous_candidate_version": previousCandidate,
				"target_version":             targetVersion,
			},
			CreatedAt: updatedAt,
		}); err != nil {
			logger.Warn("append rollback policy event", telemetry.ZapError(err))
		}

		c.JSON(http.StatusOK, authzPolicyRollbackResponse{
			PolicySetID:              policySetID,
			PreviousEffective:        previousEffective,
			PreviousActiveVersion:    previousActive,
			PreviousCandidateVersion: previousCandidate,
			ActiveVersion:            targetVersion,
			RolloutMode:              db.AuthzPolicyRolloutModeDisabled,
			UpdatedAt:                updatedAt,
		})
	}
}

func effectiveRollbackActor(c *gin.Context, explicit string) string {
	normalized := strings.TrimSpace(explicit)
	if normalized != "" {
		return normalized
	}
	return triageActorFromContext(c)
}

func effectiveVersionBeforeRollback(rollout db.AuthzPolicyRollout) *int {
	if rollout.Mode == db.AuthzPolicyRolloutModeEnforce &&
		rollout.CandidateVersion != nil &&
		rolloutVersionValidated(rollout, *rollout.CandidateVersion) {
		return cloneIntPointer(rollout.CandidateVersion)
	}
	return cloneIntPointer(rollout.ActiveVersion)
}

func appendValidatedVersion(existing []int, target int) []int {
	versions := append([]int(nil), existing...)
	if target > 0 {
		versions = append(versions, target)
	}
	seen := map[int]struct{}{}
	normalized := make([]int, 0, len(versions))
	for _, version := range versions {
		if version <= 0 {
			continue
		}
		if _, exists := seen[version]; exists {
			continue
		}
		seen[version] = struct{}{}
		normalized = append(normalized, version)
	}
	sort.Ints(normalized)
	return normalized
}

func cloneIntPointer(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
