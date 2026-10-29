// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

func TestEKSClusterRecordPreservesDescribeObservation(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cluster := ekstypes.Cluster{
		Arn:  aws.String("arn:aws:eks:us-east-1:123456789012:cluster/demo"),
		Name: aws.String("demo"), Status: ekstypes.ClusterStatusActive,
		Version: aws.String("1.32"), PlatformVersion: aws.String("eks.1"),
		RoleArn:  aws.String("arn:aws:iam::123456789012:role/demo"),
		Endpoint: aws.String("https://example.invalid"), CreatedAt: &created,
		Tags:               map[string]string{"team": "platform"},
		Identity:           &ekstypes.Identity{Oidc: &ekstypes.OIDC{Issuer: aws.String("https://issuer.example.invalid/id/demo")}},
		ResourcesVpcConfig: &ekstypes.VpcConfigResponse{VpcId: aws.String("vpc-1"), SubnetIds: []string{"subnet-1"}, EndpointPrivateAccess: true},
	}
	row, err := eksClusterRecord(cluster, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if row.Resource == nil {
		t.Fatal("typed EKS cluster resource missing")
	}
	if row.Resource.ResourceType != "aws_eks_cluster" || row.Resource.ResourceID != aws.ToString(cluster.Arn) || row.Resource.State != "ACTIVE" {
		t.Fatalf("cluster identity changed: %+v", row.Resource)
	}
	if row.Resource.Attributes["version"] != "1.32" || row.Resource.Attributes["created_at"] != created || row.Resource.Tags["team"] != "platform" {
		t.Fatalf("cluster metadata missing: %+v", row.Resource)
	}
	vpc, ok := row.Resource.Attributes["vpc_config"].(map[string]any)
	if !ok || vpc["vpc_id"] != "vpc-1" || vpc["endpoint_private_access"] != true {
		t.Fatalf("cluster VPC observation missing: %+v", row.Resource.Attributes["vpc_config"])
	}
	oidc, ok := row.Resource.Attributes["oidc_provider"].(map[string]any)
	if !ok || oidc["issuer_url"] != "https://issuer.example.invalid/id/demo" || oidc["arn"] != "" {
		t.Fatalf("EKS issuer must not assert an IAM provider: %+v", row.Resource.Attributes["oidc_provider"])
	}
}

func TestEKSClusterRecordRejectsMissingIdentity(t *testing.T) {
	if _, err := eksClusterRecord(ekstypes.Cluster{}, "us-east-1"); err == nil {
		t.Fatal("missing cluster identity was accepted")
	}
}
