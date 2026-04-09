package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
)

func TestCompileRouteAuthorizationPolicyBundleRejectsInvalidABACPredicate(t *testing.T) {
	bundle := routeAuthorizationPolicyBundle{
		SchemaVersion: routeAuthorizationPolicyBundleSchemaV1,
		RoutePolicies: []routePolicyDefinition{{
			Method:       "PATCH",
			Path:         "/v1/findings/:finding_id/triage",
			Action:       policyActionFindingsTriage,
			ResourceType: "finding",
		}},
		RBACActionRole: map[string][]string{
			policyActionFindingsTriage: {scopeWrite, scopeAdmin},
		},
		ABACPolicies: map[string]abacActionPolicy{
			policyActionFindingsTriage: {
				AnyOf: []abacClause{{
					AllOf: []abacPredicate{{
						Source:        abacAttributeSourceSubject,
						Key:           policyAttributeOwnerTeam,
						Operator:      abacOperatorEqualsAttribute,
						CompareSource: abacAttributeSourceResource,
					}},
				}},
			},
		},
	}

	_, err := compileRouteAuthorizationPolicyBundle(bundle)
	if err == nil {
		t.Fatal("expected invalid abac expression to fail compilation")
	}
	if !strings.Contains(err.Error(), "compare_key") {
		t.Fatalf("expected compare_key error, got %v", err)
	}
}

func TestCompileRouteAuthorizationPolicyBundleRejectsInvalidReBACRelation(t *testing.T) {
	bundle := routeAuthorizationPolicyBundle{
		SchemaVersion: routeAuthorizationPolicyBundleSchemaV1,
		RoutePolicies: []routePolicyDefinition{{
			Method:       "PATCH",
			Path:         "/v1/findings/:finding_id/triage",
			Action:       policyActionFindingsTriage,
			ResourceType: "finding",
		}},
		RBACActionRole: map[string][]string{
			policyActionFindingsTriage: {scopeWrite, scopeAdmin},
		},
		ABACPolicies: map[string]abacActionPolicy{
			policyActionFindingsTriage: {
				AnyOf: []abacClause{{}},
			},
		},
		ReBACPolicies: map[string]rebacActionPolicy{
			policyActionFindingsTriage: {
				AnyOf: []rebacRelationPath{{Relations: []string{"viewer"}}},
			},
		},
	}

	_, err := compileRouteAuthorizationPolicyBundle(bundle)
	if err == nil {
		t.Fatal("expected invalid rebac relation to fail compilation")
	}
	if !strings.Contains(err.Error(), "unsupported relation") {
		t.Fatalf("expected unsupported relation error, got %v", err)
	}
}

func TestCentralPolicyRuntimeResolverFallsBackWhenNoActiveRollout(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := testAuthzPolicyScopeContext()
	resolver := newCentralPolicyRuntimeResolverWithPolicySet(store, defaultCentralPolicySetID)

	runtimePolicy, err := resolver.Resolve(ctx)
	if err != nil {
		t.Fatalf("resolve runtime policy fallback: %v", err)
	}
	if runtimePolicy.Source != "built_in_default" {
		t.Fatalf("expected built-in fallback source, got %q", runtimePolicy.Source)
	}
	if _, exists := runtimePolicy.Registry.lookup("POST", "/v1/scans"); !exists {
		t.Fatal("expected built-in route policy for POST /v1/scans")
	}
}

func TestCentralPolicyRuntimeResolverUsesPersistedActiveVersion(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := testAuthzPolicyScopeContext()
	resolver := newCentralPolicyRuntimeResolverWithPolicySet(store, defaultCentralPolicySetID)

	if err := store.UpsertAuthzPolicySet(ctx, db.AuthzPolicySet{
		PolicySetID: defaultCentralPolicySetID,
		DisplayName: "Central Authorization",
		CreatedBy:   "test",
	}); err != nil {
		t.Fatalf("upsert policy set: %v", err)
	}

	bundle := routeAuthorizationPolicyBundle{
		SchemaVersion: routeAuthorizationPolicyBundleSchemaV1,
		RoutePolicies: []routePolicyDefinition{{
			Method:       "GET",
			Path:         "/v1/findings",
			Action:       policyActionFindingsRead,
			ResourceType: "finding",
		}},
		RBACActionRole: map[string][]string{
			policyActionFindingsRead: {scopeRead, scopeWrite, scopeAdmin},
		},
		ABACPolicies: map[string]abacActionPolicy{
			policyActionFindingsRead: {
				AnyOf: []abacClause{{}},
			},
		},
	}
	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal policy bundle: %v", err)
	}

	createdVersion, err := store.CreateAuthzPolicyVersion(ctx, db.AuthzPolicyVersion{
		PolicySetID: defaultCentralPolicySetID,
		Version:     1,
		Bundle:      string(bundleBytes),
		CreatedBy:   "test",
	})
	if err != nil {
		t.Fatalf("create policy version: %v", err)
	}

	if err := store.UpsertAuthzPolicyRollout(ctx, db.AuthzPolicyRollout{
		PolicySetID:       defaultCentralPolicySetID,
		ActiveVersion:     &createdVersion.Version,
		Mode:              db.AuthzPolicyRolloutModeEnforce,
		ValidatedVersions: []int{createdVersion.Version},
		CanaryPercentage:  100,
		UpdatedBy:         "test",
	}); err != nil {
		t.Fatalf("upsert policy rollout: %v", err)
	}

	runtimePolicy, err := resolver.Resolve(ctx)
	if err != nil {
		t.Fatalf("resolve runtime policy persisted active version: %v", err)
	}
	if runtimePolicy.Source != "persisted_active_version" {
		t.Fatalf("expected persisted source, got %q", runtimePolicy.Source)
	}
	if runtimePolicy.Version != 1 {
		t.Fatalf("expected active version 1, got %d", runtimePolicy.Version)
	}
	policy, exists := runtimePolicy.Registry.lookup("GET", "/v1/findings")
	if !exists {
		t.Fatal("expected persisted route policy for GET /v1/findings")
	}
	if policy.Action != policyActionFindingsRead {
		t.Fatalf("expected persisted action %q, got %q", policyActionFindingsRead, policy.Action)
	}
}

func TestCentralPolicyRuntimeResolverUsesActiveVersionWhenRolloutIsShadow(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := testAuthzPolicyScopeContext()
	resolver := newCentralPolicyRuntimeResolverWithPolicySet(store, defaultCentralPolicySetID)

	if err := store.UpsertAuthzPolicySet(ctx, db.AuthzPolicySet{
		PolicySetID: defaultCentralPolicySetID,
		DisplayName: "Central Authorization",
		CreatedBy:   "test",
	}); err != nil {
		t.Fatalf("upsert policy set: %v", err)
	}

	bundle := routeAuthorizationPolicyBundle{
		SchemaVersion: routeAuthorizationPolicyBundleSchemaV1,
		RoutePolicies: []routePolicyDefinition{{
			Method:       "GET",
			Path:         "/v1/findings",
			Action:       policyActionFindingsRead,
			ResourceType: "finding",
		}},
		RBACActionRole: map[string][]string{
			policyActionFindingsRead: {scopeRead, scopeWrite, scopeAdmin},
		},
		ABACPolicies: map[string]abacActionPolicy{
			policyActionFindingsRead: {
				AnyOf: []abacClause{{}},
			},
		},
	}
	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal policy bundle: %v", err)
	}
	createdVersion, err := store.CreateAuthzPolicyVersion(ctx, db.AuthzPolicyVersion{
		PolicySetID: defaultCentralPolicySetID,
		Version:     1,
		Bundle:      string(bundleBytes),
		CreatedBy:   "test",
	})
	if err != nil {
		t.Fatalf("create policy version: %v", err)
	}
	if err := store.UpsertAuthzPolicyRollout(ctx, db.AuthzPolicyRollout{
		PolicySetID:        defaultCentralPolicySetID,
		ActiveVersion:      &createdVersion.Version,
		Mode:               db.AuthzPolicyRolloutModeShadow,
		CanaryPercentage:   50,
		ValidatedVersions:  []int{createdVersion.Version},
		TenantAllowlist:    []string{"tenant-a"},
		WorkspaceAllowlist: []string{"workspace-a"},
		UpdatedBy:          "test",
	}); err != nil {
		t.Fatalf("upsert policy rollout: %v", err)
	}

	runtimePolicy, err := resolver.Resolve(ctx)
	if err != nil {
		t.Fatalf("resolve runtime policy for shadow mode: %v", err)
	}
	if runtimePolicy.Source != "persisted_active_version" {
		t.Fatalf("expected active-version source for shadow mode, got %q", runtimePolicy.Source)
	}
	if runtimePolicy.RolloutMode != db.AuthzPolicyRolloutModeShadow {
		t.Fatalf("expected shadow rollout mode, got %q", runtimePolicy.RolloutMode)
	}
	if runtimePolicy.Version != createdVersion.Version {
		t.Fatalf("expected current version %d, got %d", createdVersion.Version, runtimePolicy.Version)
	}
	if runtimePolicy.Rollout.CanaryPercentage != 50 {
		t.Fatalf("expected rollout canary percentage 50, got %d", runtimePolicy.Rollout.CanaryPercentage)
	}
	if len(runtimePolicy.Rollout.TenantAllowlist) != 1 || runtimePolicy.Rollout.TenantAllowlist[0] != "tenant-a" {
		t.Fatalf("unexpected rollout tenant allowlist: %+v", runtimePolicy.Rollout.TenantAllowlist)
	}
}

func TestValidateAuthzPolicyRolloutActivationRejectsInvalidBundle(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := testAuthzPolicyScopeContext()

	if err := store.UpsertAuthzPolicySet(ctx, db.AuthzPolicySet{
		PolicySetID: defaultCentralPolicySetID,
		DisplayName: "Central Authorization",
		CreatedBy:   "test",
	}); err != nil {
		t.Fatalf("upsert policy set: %v", err)
	}

	invalidBundle := routeAuthorizationPolicyBundle{
		SchemaVersion: routeAuthorizationPolicyBundleSchemaV1,
		RoutePolicies: []routePolicyDefinition{{
			Method:       "PATCH",
			Path:         "/v1/findings/:finding_id/triage",
			Action:       policyActionFindingsTriage,
			ResourceType: "finding",
		}},
		RBACActionRole: map[string][]string{
			policyActionFindingsTriage: {scopeWrite, scopeAdmin},
		},
		ABACPolicies: map[string]abacActionPolicy{
			policyActionFindingsTriage: {
				AnyOf: []abacClause{{
					AllOf: []abacPredicate{{
						Source:   abacAttributeSourceSubject,
						Key:      policyAttributeOwnerTeam,
						Operator: abacOperatorOneOf,
					}},
				}},
			},
		},
	}
	bundleBytes, err := json.Marshal(invalidBundle)
	if err != nil {
		t.Fatalf("marshal invalid bundle: %v", err)
	}
	version, err := store.CreateAuthzPolicyVersion(ctx, db.AuthzPolicyVersion{
		PolicySetID: defaultCentralPolicySetID,
		Version:     1,
		Bundle:      string(bundleBytes),
		CreatedBy:   "test",
	})
	if err != nil {
		t.Fatalf("create invalid policy version: %v", err)
	}
	rollout := db.AuthzPolicyRollout{
		PolicySetID:   defaultCentralPolicySetID,
		ActiveVersion: &version.Version,
		Mode:          db.AuthzPolicyRolloutModeEnforce,
	}
	if err := validateAuthzPolicyRolloutActivation(ctx, store, defaultCentralPolicySetID, rollout); err == nil {
		t.Fatal("expected invalid bundle to fail activation validation")
	}
}

func TestCentralPolicyRuntimeResolverFallbackBranches(t *testing.T) {
	ctx := testAuthzPolicyScopeContext()

	var nilResolver *storeBackedCentralPolicyRuntimeResolver
	runtimePolicy, err := nilResolver.Resolve(ctx)
	if err != nil {
		t.Fatalf("resolve nil runtime resolver: %v", err)
	}
	if runtimePolicy.Source != "built_in_default" {
		t.Fatalf("expected built-in source for nil resolver, got %q", runtimePolicy.Source)
	}
	if runtimePolicy.PolicySetID != defaultCentralPolicySetID {
		t.Fatalf("expected default policy set for nil resolver, got %q", runtimePolicy.PolicySetID)
	}

	resolver := newCentralPolicyRuntimeResolverWithPolicySet(nil, "   ")
	runtimePolicy, err = resolver.Resolve(ctx)
	if err != nil {
		t.Fatalf("resolve resolver with nil store: %v", err)
	}
	if runtimePolicy.Source != "built_in_default" {
		t.Fatalf("expected built-in source for nil store, got %q", runtimePolicy.Source)
	}
	if runtimePolicy.PolicySetID != defaultCentralPolicySetID {
		t.Fatalf("expected default policy set for nil store resolver, got %q", runtimePolicy.PolicySetID)
	}
	if _, exists := runtimePolicy.Registry.lookup("POST", "/v1/scans"); !exists {
		t.Fatal("expected built-in route policy in fallback runtime")
	}
}

func TestCentralPolicyRuntimeResolverErrorAndRolloutFallbackPaths(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := testAuthzPolicyScopeContext()
	resolver := newCentralPolicyRuntimeResolver(store)

	if _, err := resolver.Resolve(context.Background()); err == nil {
		t.Fatal("expected scope error when resolving runtime without scope context")
	}

	if err := store.UpsertAuthzPolicySet(ctx, db.AuthzPolicySet{
		PolicySetID: defaultCentralPolicySetID,
		DisplayName: "Central Authorization",
		CreatedBy:   "test",
	}); err != nil {
		t.Fatalf("upsert policy set: %v", err)
	}

	if err := store.UpsertAuthzPolicyRollout(ctx, db.AuthzPolicyRollout{
		PolicySetID: defaultCentralPolicySetID,
		Mode:        db.AuthzPolicyRolloutModeEnforce,
		UpdatedBy:   "test",
	}); err != nil {
		t.Fatalf("upsert enforce rollout without active version: %v", err)
	}

	runtimePolicy, err := resolver.Resolve(ctx)
	if err != nil {
		t.Fatalf("resolve runtime for enforce-without-active rollout: %v", err)
	}
	if runtimePolicy.Source != "built_in_default" {
		t.Fatalf("expected built-in fallback when enforce rollout has no active version, got %q", runtimePolicy.Source)
	}
	if runtimePolicy.RolloutMode != db.AuthzPolicyRolloutModeEnforce {
		t.Fatalf("expected rollout mode to reflect enforce fallback, got %q", runtimePolicy.RolloutMode)
	}
}

func TestPolicyBundleCompilerValidationBranches(t *testing.T) {
	if _, err := compileRouteAuthorizationPolicyBundleJSON("   "); err == nil {
		t.Fatal("expected empty policy bundle to fail")
	}
	if _, err := compileRouteAuthorizationPolicyBundleJSON("{not-json"); err == nil {
		t.Fatal("expected malformed policy bundle JSON to fail")
	}

	if _, err := compileRouteAuthorizationPolicyBundle(routeAuthorizationPolicyBundle{
		SchemaVersion: "identrail.authz.route_policy_bundle.v0",
	}); err == nil {
		t.Fatal("expected unsupported schema version to fail")
	}

	if _, _, err := compileRoutePolicies(nil); err == nil {
		t.Fatal("expected empty route policy list to fail")
	}

	_, _, err := compileRoutePolicies([]routePolicyDefinition{
		{Method: "GET", Path: "/v1/findings", Action: "findings_read", ResourceType: "finding"},
		{Method: "GET", Path: "/v1/findings", Action: "findings_read", ResourceType: "finding"},
	})
	if err == nil {
		t.Fatal("expected duplicate route policy definition to fail")
	}

	if _, err := normalizeRoutePolicyDefinition(routePolicyDefinition{
		Method:       "TRACE",
		Path:         "/v1/findings",
		Action:       "findings_read",
		ResourceType: "finding",
	}); err == nil {
		t.Fatal("expected unsupported method to fail")
	}
	if _, err := normalizeRoutePolicyDefinition(routePolicyDefinition{
		Method:          "GET",
		Path:            "/v1/findings/:finding_id",
		Action:          "findings_read",
		ResourceType:    "finding",
		ResourceIDParam: "scan_id",
	}); err == nil {
		t.Fatal("expected missing route parameter reference to fail")
	}

	routeActions := map[string]struct{}{"findings_read": {}, "scans_run": {}}
	if _, err := compileRBACRoleGrants(map[string][]string{}, routeActions); err == nil {
		t.Fatal("expected empty rbac grants to fail")
	}
	if _, err := compileRBACRoleGrants(map[string][]string{
		"findings_read": {"  "},
	}, routeActions); err == nil {
		t.Fatal("expected empty rbac role list to fail")
	}
	if _, err := compileRBACRoleGrants(map[string][]string{
		"findings_read": {scopeRead},
	}, routeActions); err == nil {
		t.Fatal("expected missing action role grant to fail")
	}

	if _, err := compileABACPolicies(map[string]abacActionPolicy{}, routeActions); err == nil {
		t.Fatal("expected empty abac policies to fail")
	}
	if _, err := compileABACPolicies(map[string]abacActionPolicy{
		"findings_read": {AnyOf: []abacClause{{}}},
	}, routeActions); err == nil {
		t.Fatal("expected missing abac policy for route action to fail")
	}

	if _, err := compileReBACPolicies(map[string]rebacActionPolicy{
		"findings_read": {AnyOf: []rebacRelationPath{{}}},
	}, map[string]struct{}{"findings_read": {}}); err == nil {
		t.Fatal("expected rebac path without relations to fail")
	}
}

func TestPolicyBundleValidationHelpersRejectInvalidInputs(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := testAuthzPolicyScopeContext()

	if err := store.UpsertAuthzPolicySet(ctx, db.AuthzPolicySet{
		PolicySetID: defaultCentralPolicySetID,
		DisplayName: "Central Authorization",
		CreatedBy:   "test",
	}); err != nil {
		t.Fatalf("upsert policy set: %v", err)
	}
	versionBundle := defaultBuiltInRouteAuthorizationPolicyBundle()
	versionBundleBytes, err := json.Marshal(versionBundle)
	if err != nil {
		t.Fatalf("marshal default bundle: %v", err)
	}
	version, err := store.CreateAuthzPolicyVersion(ctx, db.AuthzPolicyVersion{
		PolicySetID: defaultCentralPolicySetID,
		Version:     1,
		Bundle:      string(versionBundleBytes),
		CreatedBy:   "test",
	})
	if err != nil {
		t.Fatalf("create policy version: %v", err)
	}

	if err := validateABACActionPolicy(abacActionPolicy{
		OnNoMatch: "unsupported",
	}, "abac_policies.findings_read"); err == nil {
		t.Fatal("expected invalid on_no_match value to fail")
	}
	if err := validateABACPredicate(abacPredicate{
		Source:   abacAttributeSourceSubject,
		Key:      policyAttributeOwnerTeam,
		Operator: abacOperatorEquals,
	}); err == nil {
		t.Fatal("expected equals predicate without value to fail")
	}
	if err := validateABACPredicate(abacPredicate{
		Source:   abacAttributeSourceSubject,
		Key:      policyAttributeOwnerTeam,
		Operator: abacOperatorOneOf,
		Values:   []string{" ", ""},
	}); err == nil {
		t.Fatal("expected one_of predicate without non-empty values to fail")
	}
	if err := validateABACPredicate(abacPredicate{
		Source:        abacAttributeSourceSubject,
		Key:           policyAttributeOwnerTeam,
		Operator:      abacOperatorEqualsAttribute,
		CompareSource: "invalid",
		CompareKey:    policyAttributeOwnerTeam,
	}); err == nil {
		t.Fatal("expected equals_attribute predicate with invalid compare source to fail")
	}

	if err := validateReBACActionPolicy(rebacActionPolicy{
		AnyOf: []rebacRelationPath{{Relations: []string{db.AuthzRelationshipOwns}}},
	}, "rebac_policies.findings_read"); err != nil {
		t.Fatalf("expected supported rebac relation to validate, got %v", err)
	}

	if err := validateAuthzPolicyRolloutActivation(context.Background(), nil, defaultCentralPolicySetID, db.AuthzPolicyRollout{}); err == nil {
		t.Fatal("expected nil store rollout validation to fail")
	}
	if err := validateAuthzPolicyRolloutActivation(context.Background(), db.NewMemoryStore(), "   ", db.AuthzPolicyRollout{}); err == nil {
		t.Fatal("expected empty policy set id rollout validation to fail")
	}
	if err := validateAuthzPolicyRolloutActivation(ctx, store, defaultCentralPolicySetID, db.AuthzPolicyRollout{
		PolicySetID:       defaultCentralPolicySetID,
		Mode:              db.AuthzPolicyRolloutModeEnforce,
		ActiveVersion:     &version.Version,
		ValidatedVersions: []int{},
	}); err == nil {
		t.Fatal("expected enforce activation without validated version to fail")
	}
	if err := validateAuthzPolicyVersionBundle(context.Background(), db.NewMemoryStore(), defaultCentralPolicySetID, 0); err == nil {
		t.Fatal("expected non-positive version validation to fail")
	}
}

func testAuthzPolicyScopeContext() context.Context {
	return db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
}
