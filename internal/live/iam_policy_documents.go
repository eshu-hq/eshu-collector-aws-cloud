// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	iamservice "github.com/eshu-hq/eshu-collector-aws-cloud/internal/service/iam"
)

// maxIAMPolicyDocumentsPerPrincipal bounds the per-principal managed-policy
// document fan-out. Reading a managed policy document costs a GetPolicy +
// GetPolicyVersion pair, so an unbounded loop over a principal with many
// attachments is an N+1 against IAM. Statements past the cap are skipped
// rather than fetched, mirroring the in-tree awssdk cap.
const maxIAMPolicyDocumentsPerPrincipal = 25

// Principal types for emitted IAM permission observations. They repeat the
// in-tree posture literals (posture.PrincipalTypeAWSRole/User); this module
// has no posture seam, so the literals are pinned here with that provenance.
const (
	iamPrincipalTypeRole = "aws_iam_role"
	iamPrincipalTypeUser = "aws_iam_user"
)

// iamRolePolicyAPI is the document-read surface for roles: the inline fetch
// plus the managed GetPolicy + GetPolicyVersion pair. List/detail reads stay
// on iamRoleAPI so fakes only grow the document methods they exercise.
type iamRolePolicyAPI interface {
	GetRolePolicy(context.Context, *awsiam.GetRolePolicyInput, ...func(*awsiam.Options)) (*awsiam.GetRolePolicyOutput, error)
	GetPolicy(context.Context, *awsiam.GetPolicyInput, ...func(*awsiam.Options)) (*awsiam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *awsiam.GetPolicyVersionInput, ...func(*awsiam.Options)) (*awsiam.GetPolicyVersionOutput, error)
}

// iamManagedPolicyAPI is the managed-document read pair both readers share.
type iamManagedPolicyAPI interface {
	GetPolicy(context.Context, *awsiam.GetPolicyInput, ...func(*awsiam.Options)) (*awsiam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *awsiam.GetPolicyVersionInput, ...func(*awsiam.Options)) (*awsiam.GetPolicyVersionOutput, error)
}

// iamUserPolicyAPI is the document-read surface for users: the inline fetch
// plus the managed GetPolicy + GetPolicyVersion pair.
type iamUserPolicyAPI interface {
	GetUserPolicy(context.Context, *awsiam.GetUserPolicyInput, ...func(*awsiam.Options)) (*awsiam.GetUserPolicyOutput, error)
	GetPolicy(context.Context, *awsiam.GetPolicyInput, ...func(*awsiam.Options)) (*awsiam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *awsiam.GetPolicyVersionInput, ...func(*awsiam.Options)) (*awsiam.GetPolicyVersionOutput, error)
}

// iamRoleStatements assembles the normalized, metadata-only permission
// statements for one role: the trust policy, every inline policy document,
// the attached managed policy documents up to the per-principal fan-out cap,
// and the single permissions-boundary managed policy document when present.
// A denied document degrades to one optional denial beside the surviving
// statements; any other read or parse failure aborts with an error.
func iamRoleStatements(ctx context.Context, api iamRolePolicyAPI, roleName, rawTrust string, attached, inlineNames []string, boundaryPolicyARN string) ([]iamservice.PolicyStatement, *optionalReadDenied, error) {
	var statements []iamservice.PolicyStatement
	var denials []optionalDenial

	trust, err := normalizeIAMTrustPolicyDocument(rawTrust)
	if err != nil {
		return nil, nil, fmt.Errorf("normalize IAM trust policy for role %q: %w", roleName, err)
	}
	statements = append(statements, trust...)

	for _, name := range inlineNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		document, denial, err := getIAMRolePolicyDocument(ctx, api, roleName, name)
		if err != nil {
			return nil, nil, err
		}
		if denial != nil {
			denials = append(denials, *denial)
			continue
		}
		normalized, err := normalizeIAMPolicyDocument(document, iamservice.PolicySourceInline, "", name)
		if err != nil {
			return nil, nil, fmt.Errorf("normalize inline policy %q for role %q: %w", name, roleName, err)
		}
		statements = append(statements, normalized...)
	}

	managed, denial, err := boundedIAMManagedPolicyStatements(ctx, api, attached)
	if err != nil {
		return nil, nil, err
	}
	if denial != nil {
		denials = append(denials, denial.denials...)
	}
	statements = append(statements, managed...)

	boundary, denial, err := iamPermissionBoundaryStatements(ctx, api, boundaryPolicyARN)
	if err != nil {
		return nil, nil, err
	}
	if denial != nil {
		denials = append(denials, denial.denials...)
	}
	statements = append(statements, boundary...)

	if len(denials) > 0 {
		return statements, &optionalReadDenied{denials: denials}, nil
	}
	return statements, nil, nil
}

// iamUserStatements assembles the normalized inline and attached managed
// policy statements for one user, bounding the managed-policy fan-out, plus
// the single permissions-boundary managed policy document when present.
func iamUserStatements(ctx context.Context, api iamUserPolicyAPI, userName string, attached, inlineNames []string, boundaryPolicyARN string) ([]iamservice.PolicyStatement, *optionalReadDenied, error) {
	var statements []iamservice.PolicyStatement
	var denials []optionalDenial

	for _, name := range inlineNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		document, denial, err := getIAMUserPolicyDocument(ctx, api, userName, name)
		if err != nil {
			return nil, nil, err
		}
		if denial != nil {
			denials = append(denials, *denial)
			continue
		}
		normalized, err := normalizeIAMPolicyDocument(document, iamservice.PolicySourceInline, "", name)
		if err != nil {
			return nil, nil, fmt.Errorf("normalize inline policy %q for user %q: %w", name, userName, err)
		}
		statements = append(statements, normalized...)
	}

	managed, denial, err := boundedIAMManagedPolicyStatements(ctx, api, attached)
	if err != nil {
		return nil, nil, err
	}
	if denial != nil {
		denials = append(denials, denial.denials...)
	}
	statements = append(statements, managed...)

	boundary, denial, err := iamPermissionBoundaryStatements(ctx, api, boundaryPolicyARN)
	if err != nil {
		return nil, nil, err
	}
	if denial != nil {
		denials = append(denials, denial.denials...)
	}
	statements = append(statements, boundary...)

	if len(denials) > 0 {
		return statements, &optionalReadDenied{denials: denials}, nil
	}
	return statements, nil, nil
}

// boundedIAMManagedPolicyStatements reads and normalizes attached managed
// policy documents up to maxIAMPolicyDocumentsPerPrincipal. Splitting the
// cap and iteration out keeps the per-principal fan-out bound unit testable:
// at most cap documents are fetched regardless of how many ARNs attach.
func boundedIAMManagedPolicyStatements(ctx context.Context, api iamManagedPolicyAPI, policyARNs []string) ([]iamservice.PolicyStatement, *optionalReadDenied, error) {
	var statements []iamservice.PolicyStatement
	var denials []optionalDenial
	limit := len(policyARNs)
	if limit > maxIAMPolicyDocumentsPerPrincipal {
		limit = maxIAMPolicyDocumentsPerPrincipal
	}
	for i := 0; i < limit; i++ {
		policyARN := strings.TrimSpace(policyARNs[i])
		if policyARN == "" {
			continue
		}
		document, denial, err := getIAMManagedPolicyDocument(ctx, api, policyARN)
		if err != nil {
			return nil, nil, err
		}
		if denial != nil {
			denials = append(denials, *denial)
			continue
		}
		normalized, err := normalizeIAMPolicyDocument(document, iamservice.PolicySourceAttachedManaged, policyARN, "")
		if err != nil {
			return nil, nil, fmt.Errorf("normalize managed policy %q: %w", policyARN, err)
		}
		statements = append(statements, normalized...)
	}
	if len(denials) > 0 {
		return statements, &optionalReadDenied{denials: denials}, nil
	}
	return statements, nil, nil
}

// iamPermissionBoundaryStatements reads and normalizes the single managed
// policy document attached as a permissions boundary, when present.
func iamPermissionBoundaryStatements(ctx context.Context, api iamManagedPolicyAPI, boundaryPolicyARN string) ([]iamservice.PolicyStatement, *optionalReadDenied, error) {
	policyARN := strings.TrimSpace(boundaryPolicyARN)
	if policyARN == "" {
		return nil, nil, nil
	}
	document, denial, err := getIAMManagedPolicyDocument(ctx, api, policyARN)
	if err != nil {
		return nil, nil, err
	}
	if denial != nil {
		return nil, &optionalReadDenied{denials: []optionalDenial{*denial}}, nil
	}
	normalized, err := normalizeIAMPolicyDocument(document, iamservice.PolicySourcePermissionBoundary, policyARN, "")
	if err != nil {
		return nil, nil, fmt.Errorf("normalize permission boundary policy %q: %w", policyARN, err)
	}
	return normalized, nil, nil
}

func getIAMRolePolicyDocument(ctx context.Context, api iamRolePolicyAPI, roleName, policyName string) (string, *optionalDenial, error) {
	output, err := api.GetRolePolicy(ctx, &awsiam.GetRolePolicyInput{RoleName: aws.String(roleName), PolicyName: aws.String(policyName)})
	if err != nil {
		if isIAMPolicyDenial(err) {
			return "", &optionalDenial{operation: "GetRolePolicy", resource: "role:" + roleName, effect: "permission-statements-unavailable"}, nil
		}
		return "", nil, fmt.Errorf("iam get role policy %q for role %q: %w", policyName, roleName, err)
	}
	if output == nil {
		return "", nil, nil
	}
	return aws.ToString(output.PolicyDocument), nil, nil
}

func getIAMUserPolicyDocument(ctx context.Context, api iamUserPolicyAPI, userName, policyName string) (string, *optionalDenial, error) {
	output, err := api.GetUserPolicy(ctx, &awsiam.GetUserPolicyInput{UserName: aws.String(userName), PolicyName: aws.String(policyName)})
	if err != nil {
		if isIAMPolicyDenial(err) {
			return "", &optionalDenial{operation: "GetUserPolicy", resource: "user:" + userName, effect: "permission-statements-unavailable"}, nil
		}
		return "", nil, fmt.Errorf("iam get user policy %q for user %q: %w", policyName, userName, err)
	}
	if output == nil {
		return "", nil, nil
	}
	return aws.ToString(output.PolicyDocument), nil, nil
}

// getIAMManagedPolicyDocument reads the default version document of one
// attached managed policy: the GetPolicy + GetPolicyVersion pair the
// per-principal cap bounds. A missing policy or version reads back empty so
// the caller skips it; a denial degrades to one optional denial.
func getIAMManagedPolicyDocument(ctx context.Context, api iamManagedPolicyAPI, policyARN string) (string, *optionalDenial, error) {
	policyOut, err := api.GetPolicy(ctx, &awsiam.GetPolicyInput{PolicyArn: aws.String(policyARN)})
	if err != nil {
		if isIAMPolicyDenial(err) {
			return "", &optionalDenial{operation: "GetPolicy", resource: "policy:" + policyARN, effect: "permission-statements-unavailable"}, nil
		}
		return "", nil, fmt.Errorf("iam get managed policy %q: %w", policyARN, err)
	}
	if policyOut == nil || policyOut.Policy == nil {
		return "", nil, nil
	}
	versionID := strings.TrimSpace(aws.ToString(policyOut.Policy.DefaultVersionId))
	if versionID == "" {
		return "", nil, nil
	}
	versionOut, err := api.GetPolicyVersion(ctx, &awsiam.GetPolicyVersionInput{PolicyArn: aws.String(policyARN), VersionId: aws.String(versionID)})
	if err != nil {
		if isIAMPolicyDenial(err) {
			return "", &optionalDenial{operation: "GetPolicyVersion", resource: "policy:" + policyARN, effect: "permission-statements-unavailable"}, nil
		}
		return "", nil, fmt.Errorf("iam get managed policy version %q for %q: %w", versionID, policyARN, err)
	}
	if versionOut == nil || versionOut.PolicyVersion == nil {
		return "", nil, nil
	}
	return aws.ToString(versionOut.PolicyVersion.Document), nil, nil
}

// isIAMPolicyDenial recognizes the authorization failures that degrade one
// document read to a warning. Other API and transport failures stay fatal so
// a misconfigured scan never reads back as partial evidence.
func isIAMPolicyDenial(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
		return true
	default:
		return false
	}
}

// iamPermissionObservations projects normalized statements onto the
// collector observation the aws_iam_permission envelope accepts. The
// principal identity binds every statement to its role or user; the boundary
// keeps the legacy account-global IAM scope. Only metadata crosses: the raw
// document never reaches this projection.
func iamPermissionObservations(principalARN, principalType string, statements []iamservice.PolicyStatement) []collector.IAMPermissionObservation {
	observations := make([]collector.IAMPermissionObservation, 0, len(statements))
	for _, statement := range statements {
		observations = append(observations, collector.IAMPermissionObservation{
			Boundary:           collector.Boundary{Region: "aws-global", ServiceKind: catalog.ServiceIAM},
			PrincipalARN:       principalARN,
			PrincipalType:      principalType,
			PolicySource:       statement.Source,
			PolicyARN:          statement.PolicyARN,
			PolicyName:         statement.PolicyName,
			StatementSID:       statement.StatementSID,
			Effect:             statement.Effect,
			Actions:            statement.Actions,
			NotActions:         statement.NotActions,
			Resources:          statement.Resources,
			NotResources:       statement.NotResources,
			ConditionKeys:      statement.ConditionKeys,
			ConditionOperators: statement.ConditionOperators,
			AssumePrincipals:   statement.AssumePrincipals,
		})
	}
	return observations
}
