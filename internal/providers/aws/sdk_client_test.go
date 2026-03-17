package aws

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type fakeIAMSDKClient struct {
	listRolesFn                func(context.Context, *iam.ListRolesInput) (*iam.ListRolesOutput, error)
	listRolePoliciesFn         func(context.Context, *iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error)
	getRolePolicyFn            func(context.Context, *iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error)
	listAttachedRolePoliciesFn func(context.Context, *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error)
	getPolicyFn                func(context.Context, *iam.GetPolicyInput) (*iam.GetPolicyOutput, error)
	getPolicyVersionFn         func(context.Context, *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error)
}

func (f *fakeIAMSDKClient) ListRoles(ctx context.Context, in *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return f.listRolesFn(ctx, in)
}
func (f *fakeIAMSDKClient) ListRolePolicies(ctx context.Context, in *iam.ListRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	return f.listRolePoliciesFn(ctx, in)
}
func (f *fakeIAMSDKClient) GetRolePolicy(ctx context.Context, in *iam.GetRolePolicyInput, _ ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	return f.getRolePolicyFn(ctx, in)
}
func (f *fakeIAMSDKClient) ListAttachedRolePolicies(ctx context.Context, in *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return f.listAttachedRolePoliciesFn(ctx, in)
}
func (f *fakeIAMSDKClient) GetPolicy(ctx context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return f.getPolicyFn(ctx, in)
}
func (f *fakeIAMSDKClient) GetPolicyVersion(ctx context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return f.getPolicyVersionFn(ctx, in)
}

func TestSDKIAMAPIListRolesHydratesPolicies(t *testing.T) {
	createdAt := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	lastUsedAt := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	client := &fakeIAMSDKClient{
		listRolesFn: func(_ context.Context, in *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			if awsv2.ToInt32(in.MaxItems) != 50 {
				t.Fatalf("unexpected max items: %d", awsv2.ToInt32(in.MaxItems))
			}
			return &iam.ListRolesOutput{
				IsTruncated: true,
				Marker:      awsv2.String("next-token"),
				Roles: []iamtypes.Role{
					{
						Arn:                      awsv2.String("arn:aws:iam::123456789012:role/payments"),
						RoleName:                 awsv2.String("payments"),
						Path:                     awsv2.String("/service-role/"),
						AssumeRolePolicyDocument: awsv2.String("%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%5D%7D"),
						Description:              awsv2.String("payments role"),
						CreateDate:               &createdAt,
						MaxSessionDuration:       awsv2.Int32(3600),
						RoleLastUsed:             &iamtypes.RoleLastUsed{LastUsedDate: &lastUsedAt},
						Tags: []iamtypes.Tag{
							{Key: awsv2.String("team"), Value: awsv2.String("payments")},
						},
					},
				},
			}, nil
		},
		listRolePoliciesFn: func(_ context.Context, _ *iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{"inline-policy"}}, nil
		},
		getRolePolicyFn: func(_ context.Context, in *iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error) {
			if awsv2.ToString(in.PolicyName) != "inline-policy" {
				t.Fatalf("unexpected inline policy name: %q", awsv2.ToString(in.PolicyName))
			}
			return &iam.GetRolePolicyOutput{PolicyDocument: awsv2.String("{\"Version\":\"2012-10-17\",\"Statement\":[]}")}, nil
		},
		listAttachedRolePoliciesFn: func(_ context.Context, _ *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{
				AttachedPolicies: []iamtypes.AttachedPolicy{
					{PolicyArn: awsv2.String("arn:aws:iam::aws:policy/ReadOnlyAccess"), PolicyName: awsv2.String("ReadOnlyAccess")},
				},
			}, nil
		},
		getPolicyFn: func(_ context.Context, in *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
			if awsv2.ToString(in.PolicyArn) == "" {
				t.Fatal("expected policy arn")
			}
			return &iam.GetPolicyOutput{
				Policy: &iamtypes.Policy{DefaultVersionId: awsv2.String("v1")},
			}, nil
		},
		getPolicyVersionFn: func(_ context.Context, in *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
			if awsv2.ToString(in.VersionId) != "v1" {
				t.Fatalf("unexpected version id: %q", awsv2.ToString(in.VersionId))
			}
			return &iam.GetPolicyVersionOutput{
				PolicyVersion: &iamtypes.PolicyVersion{
					Document: awsv2.String("{\"Version\":\"2012-10-17\",\"Statement\":[]}"),
				},
			}, nil
		},
	}

	api := NewSDKIAMAPIFromClient(client)
	page, err := api.ListRoles(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("list roles failed: %v", err)
	}
	if page.NextToken != "next-token" {
		t.Fatalf("unexpected next token: %q", page.NextToken)
	}
	if len(page.Roles) != 1 {
		t.Fatalf("expected one role, got %d", len(page.Roles))
	}
	role := page.Roles[0]
	if role.Name != "payments" || role.ARN == "" {
		t.Fatalf("unexpected role: %+v", role)
	}
	if len(role.PermissionPolicies) != 2 {
		t.Fatalf("expected 2 permission policies, got %d", len(role.PermissionPolicies))
	}
	if role.Tags["team"] != "payments" {
		t.Fatalf("unexpected role tags: %+v", role.Tags)
	}
}

func TestSDKIAMAPIListRolesPropagatesError(t *testing.T) {
	api := NewSDKIAMAPIFromClient(&fakeIAMSDKClient{
		listRolesFn: func(_ context.Context, _ *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			return nil, errors.New("access denied")
		},
	})
	_, err := api.ListRoles(context.Background(), "", 10)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSDKIAMAPICollectPermissionPoliciesError(t *testing.T) {
	api := NewSDKIAMAPIFromClient(&fakeIAMSDKClient{
		listRolesFn: func(_ context.Context, _ *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{
				Roles: []iamtypes.Role{
					{Arn: awsv2.String("arn:aws:iam::123:role/app"), RoleName: awsv2.String("app")},
				},
			}, nil
		},
		listRolePoliciesFn: func(_ context.Context, _ *iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return nil, errors.New("throttled")
		},
	})
	_, err := api.ListRoles(context.Background(), "", 10)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "collect policies") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDedupePermissionPolicies(t *testing.T) {
	deduped := dedupePermissionPolicies([]IAMPermissionPolicy{
		{Name: "a", Document: "{}"},
		{Name: "a", Document: "{}"},
		{Name: " ", Document: "{}"},
		{Name: "b", Document: " "},
		{Name: "b", Document: "{\"x\":1}"},
	})
	if len(deduped) != 2 {
		t.Fatalf("expected 2 policies after dedupe, got %d", len(deduped))
	}
}
