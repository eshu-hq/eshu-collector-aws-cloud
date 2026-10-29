// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

func TestEKSAddonRecordPreservesDescribeObservation(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	modified := created.Add(time.Hour)
	addon := ekstypes.Addon{
		AddonArn:  aws.String("arn:aws:eks:us-east-1:123456789012:addon/demo/vpc-cni/abc"),
		AddonName: aws.String("vpc-cni"), ClusterName: aws.String("demo"),
		AddonVersion: aws.String("v1.20.0"), Status: ekstypes.AddonStatusActive,
		ServiceAccountRoleArn: aws.String("arn:aws:iam::123456789012:role/vpc-cni"),
		CreatedAt:             &created, ModifiedAt: &modified,
		Tags:                map[string]string{"team": "platform"},
		ConfigurationValues: aws.String("{\"token\":\"sensitive\"}"),
	}
	row, err := eksAddonRecord(addon, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if row.Resource == nil || row.Resource.ResourceType != "aws_eks_addon" || row.Resource.ResourceID != aws.ToString(addon.AddonArn) || row.Resource.State != "ACTIVE" {
		t.Fatalf("addon identity changed: %+v", row.Resource)
	}
	attrs := row.Resource.Attributes
	if attrs["addon_version"] != "v1.20.0" || attrs["cluster_name"] != "demo" || attrs["created_at"] != created || attrs["modified_at"] != modified || attrs["service_account_role_arn"] != aws.ToString(addon.ServiceAccountRoleArn) {
		t.Fatalf("addon metadata missing: %+v", attrs)
	}
	if _, ok := attrs["configuration_values"]; ok {
		t.Fatal("addon configuration values leaked into the typed observation")
	}
}

func TestEKSAddonRecordIdentityFallback(t *testing.T) {
	row, err := eksAddonRecord(ekstypes.Addon{
		ClusterName: aws.String("demo"), AddonName: aws.String("vpc-cni"),
	}, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if row.Resource == nil || row.Resource.ResourceID != "demo/vpc-cni" || row.Resource.SourceRecordID != "demo/vpc-cni" {
		t.Fatalf("addon fallback identity changed: %+v", row.Resource)
	}
	if _, err := eksAddonRecord(ekstypes.Addon{AddonName: aws.String("vpc-cni")}, "us-east-1"); err == nil {
		t.Fatal("addon without ARN or cluster name was accepted")
	}
}
