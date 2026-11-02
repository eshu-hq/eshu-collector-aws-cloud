// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

type iamUserAPI interface {
	ListUsers(context.Context, *awsiam.ListUsersInput, ...func(*awsiam.Options)) (*awsiam.ListUsersOutput, error)
	GetUser(context.Context, *awsiam.GetUserInput, ...func(*awsiam.Options)) (*awsiam.GetUserOutput, error)
	ListAttachedUserPolicies(context.Context, *awsiam.ListAttachedUserPoliciesInput, ...func(*awsiam.Options)) (*awsiam.ListAttachedUserPoliciesOutput, error)
	ListUserPolicies(context.Context, *awsiam.ListUserPoliciesInput, ...func(*awsiam.Options)) (*awsiam.ListUserPoliciesOutput, error)
	GetUserPolicy(context.Context, *awsiam.GetUserPolicyInput, ...func(*awsiam.Options)) (*awsiam.GetUserPolicyOutput, error)
	GetPolicy(context.Context, *awsiam.GetPolicyInput, ...func(*awsiam.Options)) (*awsiam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *awsiam.GetPolicyVersionInput, ...func(*awsiam.Options)) (*awsiam.GetPolicyVersionOutput, error)
}

// listIAMUserRecords reads only the metadata needed for the legacy user resource.
// A failed IAM read aborts the service so incomplete policy references are not emitted.
// Policy-document reads degrade instead: a denied document keeps the surviving
// statements behind one warning per document.
func listIAMUserRecords(ctx context.Context, client iamUserAPI, region string, identity VerifiedIdentity) ([]collector.Record, error) {
	rows := []collector.Record{}
	var denials []optionalDenial
	pages := awsiam.NewListUsersPaginator(client, &awsiam.ListUsersInput{})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iam list users: %w", err)
		}
		for _, listed := range page.Users {
			name := aws.ToString(listed.UserName)
			if strings.TrimSpace(name) == "" {
				return nil, fmt.Errorf("iam listed user has no name")
			}
			attached, err := listAttachedIAMUserPolicies(ctx, client, name)
			if err != nil {
				return nil, err
			}
			inline, err := listInlineIAMUserPolicies(ctx, client, name)
			if err != nil {
				return nil, err
			}
			out, err := client.GetUser(ctx, &awsiam.GetUserInput{UserName: aws.String(name)})
			if err != nil {
				return nil, fmt.Errorf("iam get user %q: %w", name, err)
			}
			var detail *iamtypes.User
			if out != nil {
				detail = out.User
			}
			row, err := iamUserRecord(listed, detail, attached, inline, region, identity)
			if err != nil {
				return nil, err
			}
			effective := effectiveIAMUser(listed, detail)
			boundaryARN := ""
			if effective.PermissionsBoundary != nil {
				boundaryARN = aws.ToString(effective.PermissionsBoundary.PermissionsBoundaryArn)
			}
			statements, denial, err := iamUserStatements(ctx, client, name, attached, inline, boundaryARN)
			if err != nil {
				return nil, err
			}
			if denial != nil {
				denials = append(denials, denial.denials...)
			}
			row.IAMPermissionStatements = iamPermissionObservations(row.Resource.ARN, iamPrincipalTypeUser, statements)
			rows = append(rows, row)
		}
	}
	if len(denials) > 0 {
		return rows, &optionalReadDenied{denials: denials}
	}
	return rows, nil
}

func listAttachedIAMUserPolicies(ctx context.Context, client iamUserAPI, name string) ([]string, error) {
	var arns []string
	pages := awsiam.NewListAttachedUserPoliciesPaginator(client, &awsiam.ListAttachedUserPoliciesInput{UserName: aws.String(name)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iam list attached user policies %q: %w", name, err)
		}
		for _, policy := range page.AttachedPolicies {
			arns = append(arns, aws.ToString(policy.PolicyArn))
		}
	}
	return arns, nil
}

func listInlineIAMUserPolicies(ctx context.Context, client iamUserAPI, name string) ([]string, error) {
	var names []string
	pages := awsiam.NewListUserPoliciesPaginator(client, &awsiam.ListUserPoliciesInput{UserName: aws.String(name)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iam list user policies %q: %w", name, err)
		}
		names = append(names, page.PolicyNames...)
	}
	return names, nil
}

// effectiveIAMUser resolves the detail-or-listed user both the resource row
// and the permission-statement reader use, so the two never diverge.
func effectiveIAMUser(listed iamtypes.User, detail *iamtypes.User) iamtypes.User {
	if detail != nil {
		return *detail
	}
	return listed
}

// iamUserRecord binds a regionless IAM user ARN to the verified AWS identity.
func iamUserRecord(listed iamtypes.User, detail *iamtypes.User, attached, inline []string, _ string, identity VerifiedIdentity) (collector.Record, error) {
	user := effectiveIAMUser(listed, detail)
	name := aws.ToString(listed.UserName)
	arn := strings.TrimSpace(aws.ToString(user.Arn))
	if arn == "" {
		arn = strings.TrimSpace(aws.ToString(listed.Arn))
	}
	parsed, err := awsarn.Parse(arn)
	if err != nil || parsed.Service != "iam" || parsed.Region != "" || parsed.AccountID != identity.AccountID || parsed.Partition != identity.Partition || !strings.HasPrefix(parsed.Resource, "user/") || parsed.Resource[strings.LastIndex(parsed.Resource, "/")+1:] != name {
		return collector.Record{}, fmt.Errorf("iam user ARN does not match verified account, partition, or user name")
	}
	if listedARN := strings.TrimSpace(aws.ToString(listed.Arn)); listedARN != "" && listedARN != arn {
		return collector.Record{}, fmt.Errorf("iam user detail ARN differs from listed ARN")
	}
	if detail != nil && aws.ToString(detail.UserName) != "" && aws.ToString(detail.UserName) != name {
		return collector.Record{}, fmt.Errorf("iam user detail name differs from listed name")
	}
	path := aws.ToString(user.Path)
	if strings.TrimSpace(path) == "" {
		path = aws.ToString(listed.Path)
	}
	attrs := map[string]any{
		"attached_policy_arns":     attached,
		"inline_policy_names":      inline,
		"path":                     strings.TrimSpace(path),
		"permission_boundary_arn":  "",
		"permission_boundary_type": "",
	}
	if user.PermissionsBoundary != nil {
		attrs["permission_boundary_arn"] = strings.TrimSpace(aws.ToString(user.PermissionsBoundary.PermissionsBoundaryArn))
		attrs["permission_boundary_type"] = strings.TrimSpace(string(user.PermissionsBoundary.PermissionsBoundaryType))
	}
	row := record(arn, "iam", "aws-global", name, "user")
	row.Resource = &collector.LiveResource{
		Region: "aws-global", ServiceKind: "iam", ResourceType: "aws_iam_user", ResourceID: arn, ARN: arn, Name: name,
		Attributes: attrs, CorrelationAnchors: []string{arn, strings.TrimSpace(name)}, SourceRecordID: arn,
	}
	return row, nil
}
