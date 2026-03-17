package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

const maxAWSPolicyPages = 100

// IAMSDKClient defines the subset of AWS IAM SDK calls required by the collector adapter.
type IAMSDKClient interface {
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

// SDKIAMAPI adapts AWS SDK IAM calls to the internal IAMAPI interface.
type SDKIAMAPI struct {
	client IAMSDKClient
}

var _ IAMAPI = (*SDKIAMAPI)(nil)

// NewSDKIAMAPI constructs an IAMAPI backed by the AWS SDK default credential chain.
func NewSDKIAMAPI(region string, profile string) (IAMAPI, error) {
	loadOptions := []func(*awscfg.LoadOptions) error{
		awscfg.WithRegion(strings.TrimSpace(region)),
	}
	if trimmedProfile := strings.TrimSpace(profile); trimmedProfile != "" {
		loadOptions = append(loadOptions, awscfg.WithSharedConfigProfile(trimmedProfile))
	}
	cfg, err := awscfg.LoadDefaultConfig(context.Background(), loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	return &SDKIAMAPI{client: iam.NewFromConfig(cfg)}, nil
}

// NewSDKIAMAPIFromClient creates an IAMAPI from a provided IAM SDK client.
func NewSDKIAMAPIFromClient(client IAMSDKClient) IAMAPI {
	return &SDKIAMAPI{client: client}
}

// ListRoles returns one page of roles enriched with inline and managed policy documents.
func (a *SDKIAMAPI) ListRoles(ctx context.Context, nextToken string, pageSize int32) (ListRolesPage, error) {
	input := &iam.ListRolesInput{
		MaxItems: awsv2.Int32(pageSize),
	}
	if token := strings.TrimSpace(nextToken); token != "" {
		input.Marker = awsv2.String(token)
	}
	output, err := a.client.ListRoles(ctx, input)
	if err != nil {
		return ListRolesPage{}, err
	}

	roles := make([]IAMRole, 0, len(output.Roles))
	for _, sdkRole := range output.Roles {
		if err := ctx.Err(); err != nil {
			return ListRolesPage{}, err
		}
		arn := strings.TrimSpace(awsv2.ToString(sdkRole.Arn))
		roleName := strings.TrimSpace(awsv2.ToString(sdkRole.RoleName))
		if arn == "" || roleName == "" {
			continue
		}
		policies, err := a.collectPermissionPolicies(ctx, roleName)
		if err != nil {
			return ListRolesPage{}, fmt.Errorf("collect policies for role %s: %w", roleName, err)
		}
		roles = append(roles, IAMRole{
			ARN:                      arn,
			Name:                     roleName,
			Path:                     awsv2.ToString(sdkRole.Path),
			AssumeRolePolicyDocument: awsv2.ToString(sdkRole.AssumeRolePolicyDocument),
			PermissionPolicies:       policies,
			Description:              awsv2.ToString(sdkRole.Description),
			CreatedAt:                copySDKTime(sdkRole.CreateDate),
			LastUsedAt:               copySDKLastUsed(sdkRole.RoleLastUsed),
			MaxSessionDuration:       awsv2.ToInt32(sdkRole.MaxSessionDuration),
			Tags:                     copySDKTags(sdkRole.Tags),
		})
	}

	page := ListRolesPage{Roles: roles}
	if output.IsTruncated {
		page.NextToken = strings.TrimSpace(awsv2.ToString(output.Marker))
	}
	return page, nil
}

func (a *SDKIAMAPI) collectPermissionPolicies(ctx context.Context, roleName string) ([]IAMPermissionPolicy, error) {
	inlineNames, err := a.listInlinePolicyNames(ctx, roleName)
	if err != nil {
		return nil, err
	}
	policies := make([]IAMPermissionPolicy, 0, len(inlineNames)+4)

	for _, name := range inlineNames {
		output, err := a.client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   awsv2.String(roleName),
			PolicyName: awsv2.String(name),
		})
		if err != nil {
			return nil, fmt.Errorf("get role inline policy %s/%s: %w", roleName, name, err)
		}
		document := strings.TrimSpace(awsv2.ToString(output.PolicyDocument))
		if document == "" {
			continue
		}
		policies = append(policies, IAMPermissionPolicy{Name: name, Document: document})
	}

	attached, err := a.listAttachedPolicies(ctx, roleName)
	if err != nil {
		return nil, err
	}
	for _, attachedPolicy := range attached {
		policyARN := strings.TrimSpace(awsv2.ToString(attachedPolicy.PolicyArn))
		if policyARN == "" {
			continue
		}
		policyName := strings.TrimSpace(awsv2.ToString(attachedPolicy.PolicyName))
		if policyName == "" {
			policyName = policyARN
		}

		getPolicyOutput, err := a.client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: awsv2.String(policyARN)})
		if err != nil {
			return nil, fmt.Errorf("get managed policy %s: %w", policyARN, err)
		}
		if getPolicyOutput.Policy == nil {
			continue
		}
		defaultVersionID := strings.TrimSpace(awsv2.ToString(getPolicyOutput.Policy.DefaultVersionId))
		if defaultVersionID == "" {
			continue
		}
		versionOutput, err := a.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: awsv2.String(policyARN),
			VersionId: awsv2.String(defaultVersionID),
		})
		if err != nil {
			return nil, fmt.Errorf("get managed policy version %s (%s): %w", policyARN, defaultVersionID, err)
		}
		if versionOutput.PolicyVersion == nil {
			continue
		}
		document := strings.TrimSpace(awsv2.ToString(versionOutput.PolicyVersion.Document))
		if document == "" {
			continue
		}
		policies = append(policies, IAMPermissionPolicy{Name: policyName, Document: document})
	}

	return dedupePermissionPolicies(policies), nil
}

func (a *SDKIAMAPI) listInlinePolicyNames(ctx context.Context, roleName string) ([]string, error) {
	names := make([]string, 0, 8)
	var marker string
	for page := 0; page < maxAWSPolicyPages; page++ {
		input := &iam.ListRolePoliciesInput{
			RoleName: awsv2.String(roleName),
			MaxItems: awsv2.Int32(defaultPageSize),
		}
		if marker != "" {
			input.Marker = awsv2.String(marker)
		}
		output, err := a.client.ListRolePolicies(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list inline policies for role %s: %w", roleName, err)
		}
		names = append(names, output.PolicyNames...)
		if !output.IsTruncated {
			return dedupeStrings(names), nil
		}
		marker = strings.TrimSpace(awsv2.ToString(output.Marker))
		if marker == "" {
			break
		}
	}
	return nil, fmt.Errorf("inline policies pagination exceeded max pages for role %s", roleName)
}

func (a *SDKIAMAPI) listAttachedPolicies(ctx context.Context, roleName string) ([]iamtypes.AttachedPolicy, error) {
	policies := make([]iamtypes.AttachedPolicy, 0, 8)
	var marker string
	for page := 0; page < maxAWSPolicyPages; page++ {
		input := &iam.ListAttachedRolePoliciesInput{
			RoleName: awsv2.String(roleName),
			MaxItems: awsv2.Int32(defaultPageSize),
		}
		if marker != "" {
			input.Marker = awsv2.String(marker)
		}
		output, err := a.client.ListAttachedRolePolicies(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list attached policies for role %s: %w", roleName, err)
		}
		policies = append(policies, output.AttachedPolicies...)
		if !output.IsTruncated {
			return policies, nil
		}
		marker = strings.TrimSpace(awsv2.ToString(output.Marker))
		if marker == "" {
			break
		}
	}
	return nil, fmt.Errorf("attached policies pagination exceeded max pages for role %s", roleName)
}

func dedupePermissionPolicies(policies []IAMPermissionPolicy) []IAMPermissionPolicy {
	if len(policies) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	result := make([]IAMPermissionPolicy, 0, len(policies))
	for _, policy := range policies {
		name := strings.TrimSpace(policy.Name)
		doc := strings.TrimSpace(policy.Document)
		if name == "" || doc == "" {
			continue
		}
		key := name + "|" + doc
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, IAMPermissionPolicy{Name: name, Document: doc})
	}
	return result
}

func copySDKTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func copySDKLastUsed(lastUsed *iamtypes.RoleLastUsed) *time.Time {
	if lastUsed == nil || lastUsed.LastUsedDate == nil {
		return nil
	}
	copy := lastUsed.LastUsedDate.UTC()
	return &copy
}

func copySDKTags(tags []iamtypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		key := strings.TrimSpace(awsv2.ToString(tag.Key))
		if key == "" {
			continue
		}
		result[key] = strings.TrimSpace(awsv2.ToString(tag.Value))
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
