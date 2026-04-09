package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

func TestAuthzPolicyRollbackEndpointSwitchesActiveVersionAndCountsRollback(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := testAuthzPolicyScopeContext()
	if err := store.UpsertAuthzPolicySet(ctx, db.AuthzPolicySet{
		PolicySetID: defaultCentralPolicySetID,
		DisplayName: "Central Authorization",
		CreatedBy:   "test",
	}); err != nil {
		t.Fatalf("upsert policy set: %v", err)
	}

	versionOne := createCentralPolicyVersionForRollbackTest(t, store, ctx, 1, []string{scopeWrite, scopeAdmin})
	versionTwo := createCentralPolicyVersionForRollbackTest(t, store, ctx, 2, []string{scopeAdmin})

	if err := store.UpsertAuthzPolicyRollout(ctx, db.AuthzPolicyRollout{
		PolicySetID:       defaultCentralPolicySetID,
		ActiveVersion:     &versionOne,
		CandidateVersion:  &versionTwo,
		Mode:              db.AuthzPolicyRolloutModeEnforce,
		CanaryPercentage:  100,
		ValidatedVersions: []int{versionOne, versionTwo},
		UpdatedBy:         "seed",
	}); err != nil {
		t.Fatalf("seed enforce rollout: %v", err)
	}

	metrics := telemetry.NewMetrics()
	svc := NewService(store, routerScanner{}, "aws")
	router := NewRouter(zap.NewNop(), metrics, svc, RouterOptions{
		RateLimitRPM:       10000,
		RateLimitBurst:     1000,
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
		APIKeyScopes: map[string][]string{
			"admin-key": {scopeRead, scopeWrite, scopeAdmin},
		},
	})

	requestBody := `{"policy_set_id":"central_authorization","target_version":1}`
	req := httptest.NewRequest(http.MethodPost, "/v1/authz/policies/rollback", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "admin-key")
	req.Header.Set(scopeHeaderTenantID, "tenant-a")
	req.Header.Set(scopeHeaderWorkspaceID, "workspace-a")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 rollback response, got %d body=%s", w.Code, w.Body.String())
	}

	var response authzPolicyRollbackResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode rollback response: %v", err)
	}
	if response.ActiveVersion != versionOne {
		t.Fatalf("expected active version %d after rollback, got %d", versionOne, response.ActiveVersion)
	}
	if response.PreviousEffective == nil || *response.PreviousEffective != versionTwo {
		t.Fatalf("expected previous effective version %d, got %+v", versionTwo, response.PreviousEffective)
	}

	rollout, err := store.GetAuthzPolicyRollout(ctx, defaultCentralPolicySetID)
	if err != nil {
		t.Fatalf("get rollout after rollback: %v", err)
	}
	if rollout.ActiveVersion == nil || *rollout.ActiveVersion != versionOne {
		t.Fatalf("unexpected active version after rollback: %+v", rollout.ActiveVersion)
	}
	if rollout.CandidateVersion != nil {
		t.Fatalf("expected candidate version cleared after rollback, got %+v", rollout.CandidateVersion)
	}
	if rollout.Mode != db.AuthzPolicyRolloutModeDisabled {
		t.Fatalf("expected disabled rollout mode after rollback, got %q", rollout.Mode)
	}
	if got := testutil.ToFloat64(metrics.AuthzPolicyRollbacksTotal); got != 1 {
		t.Fatalf("expected rollback metric 1, got %v", got)
	}
}

func TestAuthzPolicyLifecycleActivateShadowEnforceRollbackIntegration(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := testAuthzPolicyScopeContext()
	if err := store.UpsertAuthzPolicySet(ctx, db.AuthzPolicySet{
		PolicySetID: defaultCentralPolicySetID,
		DisplayName: "Central Authorization",
		CreatedBy:   "test",
	}); err != nil {
		t.Fatalf("upsert policy set: %v", err)
	}

	versionOne := createCentralPolicyVersionForRollbackTest(t, store, ctx, 1, []string{scopeWrite, scopeAdmin})
	versionTwo := createCentralPolicyVersionForRollbackTest(t, store, ctx, 2, []string{scopeAdmin})

	metrics := telemetry.NewMetrics()
	svc := NewService(store, routerScanner{}, "aws")
	router := NewRouter(zap.NewNop(), metrics, svc, RouterOptions{
		RateLimitRPM:       10000,
		RateLimitBurst:     1000,
		DefaultTenantID:    "tenant-a",
		DefaultWorkspaceID: "workspace-a",
		APIKeyScopes: map[string][]string{
			"write-key": {scopeRead, scopeWrite},
			"admin-key": {scopeRead, scopeWrite, scopeAdmin},
		},
	})

	if err := store.UpsertAuthzPolicyRollout(ctx, db.AuthzPolicyRollout{
		PolicySetID:       defaultCentralPolicySetID,
		ActiveVersion:     &versionOne,
		Mode:              db.AuthzPolicyRolloutModeDisabled,
		CanaryPercentage:  100,
		ValidatedVersions: []int{versionOne},
		UpdatedBy:         "activate",
	}); err != nil {
		t.Fatalf("activate rollout: %v", err)
	}
	assertLifecycleScanStatus(t, router, "write-key", http.StatusAccepted)

	if err := store.UpsertAuthzPolicyRollout(ctx, db.AuthzPolicyRollout{
		PolicySetID:       defaultCentralPolicySetID,
		ActiveVersion:     &versionOne,
		CandidateVersion:  &versionTwo,
		Mode:              db.AuthzPolicyRolloutModeShadow,
		CanaryPercentage:  100,
		ValidatedVersions: []int{versionOne, versionTwo},
		UpdatedBy:         "shadow",
	}); err != nil {
		t.Fatalf("shadow rollout: %v", err)
	}
	assertLifecycleScanStatus(t, router, "write-key", http.StatusAccepted)
	if got := testutil.ToFloat64(metrics.AuthzPolicyShadowEvaluationsTotal); got != 1 {
		t.Fatalf("expected one shadow evaluation, got %v", got)
	}
	if got := testutil.ToFloat64(metrics.AuthzPolicyShadowDivergencesTotal); got != 1 {
		t.Fatalf("expected one divergence, got %v", got)
	}
	if got := testutil.ToFloat64(metrics.AuthzPolicyShadowDivergenceRate); got != 1 {
		t.Fatalf("expected divergence rate 1, got %v", got)
	}

	if err := store.UpsertAuthzPolicyRollout(ctx, db.AuthzPolicyRollout{
		PolicySetID:       defaultCentralPolicySetID,
		ActiveVersion:     &versionOne,
		CandidateVersion:  &versionTwo,
		Mode:              db.AuthzPolicyRolloutModeEnforce,
		CanaryPercentage:  100,
		ValidatedVersions: []int{versionOne, versionTwo},
		UpdatedBy:         "enforce",
	}); err != nil {
		t.Fatalf("enforce rollout: %v", err)
	}
	assertLifecycleScanStatus(t, router, "write-key", http.StatusForbidden)

	rollbackRequest := httptest.NewRequest(http.MethodPost, "/v1/authz/policies/rollback", bytes.NewBufferString(`{"policy_set_id":"central_authorization","target_version":1}`))
	rollbackRequest.Header.Set("Content-Type", "application/json")
	rollbackRequest.Header.Set("X-API-Key", "admin-key")
	rollbackRequest.Header.Set(scopeHeaderTenantID, "tenant-a")
	rollbackRequest.Header.Set(scopeHeaderWorkspaceID, "workspace-a")
	rollbackResponse := httptest.NewRecorder()
	router.ServeHTTP(rollbackResponse, rollbackRequest)
	if rollbackResponse.Code != http.StatusOK {
		t.Fatalf("expected rollback success, got %d body=%s", rollbackResponse.Code, rollbackResponse.Body.String())
	}

	assertLifecycleScanStatus(t, router, "write-key", http.StatusAccepted)
	if got := testutil.ToFloat64(metrics.AuthzPolicyRollbacksTotal); got != 1 {
		t.Fatalf("expected rollback counter 1, got %v", got)
	}
	if got := testutil.ToFloat64(metrics.AuthzPolicyDecisionsByVersionTotal.WithLabelValues(
		defaultCentralPolicySetID,
		"2",
		"persisted_candidate_version",
		db.AuthzPolicyRolloutModeEnforce,
		"false",
	)); got != 1 {
		t.Fatalf("expected one denied decision for version 2 in enforce mode, got %v", got)
	}
}

func assertLifecycleScanStatus(t *testing.T, router http.Handler, apiKey string, expected int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set(scopeHeaderTenantID, "tenant-a")
	req.Header.Set(scopeHeaderWorkspaceID, "workspace-a")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != expected {
		t.Fatalf("expected status %d, got %d body=%s", expected, w.Code, w.Body.String())
	}
}

func createCentralPolicyVersionForRollbackTest(t *testing.T, store db.Store, ctx context.Context, version int, scansRunRoles []string) int {
	t.Helper()
	bundle := defaultBuiltInRouteAuthorizationPolicyBundle()
	bundle.RBACActionRole[policyActionScansRun] = append([]string(nil), scansRunRoles...)
	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal policy bundle: %v", err)
	}
	createdVersion, err := store.CreateAuthzPolicyVersion(ctx, db.AuthzPolicyVersion{
		PolicySetID: defaultCentralPolicySetID,
		Version:     version,
		Bundle:      string(bundleBytes),
		CreatedBy:   "test",
	})
	if err != nil {
		t.Fatalf("create policy version: %v", err)
	}
	return createdVersion.Version
}
