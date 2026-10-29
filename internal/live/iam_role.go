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

type iamRoleAPI interface {
	ListRoles(context.Context, *awsiam.ListRolesInput, ...func(*awsiam.Options)) (*awsiam.ListRolesOutput, error)
	GetRole(context.Context, *awsiam.GetRoleInput, ...func(*awsiam.Options)) (*awsiam.GetRoleOutput, error)
	ListAttachedRolePolicies(context.Context, *awsiam.ListAttachedRolePoliciesInput, ...func(*awsiam.Options)) (*awsiam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(context.Context, *awsiam.ListRolePoliciesInput, ...func(*awsiam.Options)) (*awsiam.ListRolePoliciesOutput, error)
}

// listIAMRoleRecords mirrors the legacy role read sequence. Every mandatory
// read fails the IAM service scan; a nil GetRole detail uses the listed role.
func listIAMRoleRecords(ctx context.Context, client iamRoleAPI, region string, identity VerifiedIdentity) ([]collector.Record, error) {
	rows := []collector.Record{}
	pages := awsiam.NewListRolesPaginator(client, &awsiam.ListRolesInput{})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iam list roles: %w", err)
		}
		for _, listed := range page.Roles {
			name := strings.TrimSpace(aws.ToString(listed.RoleName))
			if name == "" {
				return nil, fmt.Errorf("iam listed role has no name")
			}
			detailOutput, err := client.GetRole(ctx, &awsiam.GetRoleInput{RoleName: aws.String(name)})
			if err != nil {
				return nil, fmt.Errorf("iam get role %q: %w", name, err)
			}
			var detail *iamtypes.Role
			if detailOutput != nil {
				detail = detailOutput.Role
			}
			attached, err := listAttachedIAMRolePolicies(ctx, client, name)
			if err != nil {
				return nil, err
			}
			inline, err := listInlineIAMRolePolicies(ctx, client, name)
			if err != nil {
				return nil, err
			}
			row, err := iamRoleRecord(listed, detail, attached, inline, region, identity)
			if err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func listAttachedIAMRolePolicies(ctx context.Context, client iamRoleAPI, name string) ([]string, error) {
	arns := []string{}
	pages := awsiam.NewListAttachedRolePoliciesPaginator(client, &awsiam.ListAttachedRolePoliciesInput{RoleName: aws.String(name)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iam list attached role policies %q: %w", name, err)
		}
		for _, policy := range page.AttachedPolicies {
			arns = append(arns, strings.TrimSpace(aws.ToString(policy.PolicyArn)))
		}
	}
	return arns, nil
}

func listInlineIAMRolePolicies(ctx context.Context, client iamRoleAPI, name string) ([]string, error) {
	names := []string{}
	pages := awsiam.NewListRolePoliciesPaginator(client, &awsiam.ListRolePoliciesInput{RoleName: aws.String(name)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iam list role policies %q: %w", name, err)
		}
		for _, policy := range page.PolicyNames {
			names = append(names, strings.TrimSpace(policy))
		}
	}
	return names, nil
}

// iamRoleRecord retains only the legacy role resource's safe metadata fields.
// It validates provider identity before binding the observation to the claim.
func iamRoleRecord(listed iamtypes.Role, detail *iamtypes.Role, attached, inline []string, region string, identity VerifiedIdentity) (collector.Record, error) {
	role := listed
	if detail != nil {
		role = *detail
	}
	arn := strings.TrimSpace(aws.ToString(role.Arn))
	if arn == "" {
		arn = strings.TrimSpace(aws.ToString(listed.Arn))
	}
	parsed, err := awsarn.Parse(arn)
	if err != nil || parsed.Service != "iam" || !strings.HasPrefix(parsed.Resource, "role/") || parsed.AccountID != identity.AccountID || parsed.Partition != identity.Partition {
		return collector.Record{}, fmt.Errorf("iam role ARN does not match verified account and partition")
	}
	if listedARN := strings.TrimSpace(aws.ToString(listed.Arn)); listedARN != "" && listedARN != arn {
		return collector.Record{}, fmt.Errorf("iam role detail ARN differs from listed ARN")
	}
	name := strings.TrimSpace(aws.ToString(listed.RoleName))
	if name == "" {
		return collector.Record{}, fmt.Errorf("iam role has no name")
	}
	path := strings.TrimSpace(aws.ToString(role.Path))
	if path == "" {
		path = strings.TrimSpace(aws.ToString(listed.Path))
	}
	attrs := map[string]any{
		"attached_policy_arns":     append([]string{}, attached...),
		"inline_policy_names":      append([]string{}, inline...),
		"path":                     path,
		"permission_boundary_arn":  "",
		"permission_boundary_type": "",
		"trust_policy_present":     strings.TrimSpace(aws.ToString(role.AssumeRolePolicyDocument)) != "",
	}
	if role.PermissionsBoundary != nil {
		attrs["permission_boundary_arn"] = strings.TrimSpace(aws.ToString(role.PermissionsBoundary.PermissionsBoundaryArn))
		attrs["permission_boundary_type"] = strings.TrimSpace(string(role.PermissionsBoundary.PermissionsBoundaryType))
	}
	row := record(arn, "iam", region, name, "role")
	row.Resource = &collector.LiveResource{Region: region, ServiceKind: "iam", ResourceType: "aws_iam_role", ResourceID: arn, ARN: arn, Name: name,
		Attributes: attrs, CorrelationAnchors: []string{arn, name}, SourceRecordID: arn}
	return row, nil
}
