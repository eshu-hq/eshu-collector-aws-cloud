// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

func TestEKSNodegroupRecordPreservesDescribeObservation(t *testing.T) {
	nodegroup := ekstypes.Nodegroup{
		NodegroupArn:  aws.String("arn:aws:eks:us-east-1:123456789012:nodegroup/demo/workers/abc"),
		NodegroupName: aws.String("workers"), ClusterName: aws.String("demo"),
		Status: ekstypes.NodegroupStatusActive, Version: aws.String("1.32"),
		ReleaseVersion: aws.String("1.32.1"), AmiType: ekstypes.AMITypesAl2023X8664Standard,
		CapacityType: ekstypes.CapacityTypesOnDemand, NodeRole: aws.String("arn:aws:iam::123456789012:role/workers"),
		InstanceTypes: []string{"m6i.large"}, Subnets: []string{"subnet-1"},
		ScalingConfig: &ekstypes.NodegroupScalingConfig{DesiredSize: aws.Int32(3), MinSize: aws.Int32(1), MaxSize: aws.Int32(5)},
		Tags:          map[string]string{"team": "platform"},
	}
	row, err := eksNodegroupRecord(nodegroup, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if row.Resource == nil || row.Resource.ResourceType != "aws_eks_nodegroup" || row.Resource.ResourceID != aws.ToString(nodegroup.NodegroupArn) || row.Resource.State != "ACTIVE" {
		t.Fatalf("nodegroup identity changed: %+v", row.Resource)
	}
	attrs := row.Resource.Attributes
	if attrs["cluster_name"] != "demo" || attrs["version"] != "1.32" || attrs["release_version"] != "1.32.1" || attrs["ami_type"] != string(nodegroup.AmiType) || attrs["capacity_type"] != string(nodegroup.CapacityType) || attrs["node_role_arn"] != aws.ToString(nodegroup.NodeRole) {
		t.Fatalf("nodegroup metadata missing: %+v", attrs)
	}
	scaling, ok := attrs["scaling_config"].(map[string]any)
	if !ok || scaling["desired_size"] != int32(3) || scaling["min_size"] != int32(1) || scaling["max_size"] != int32(5) {
		t.Fatalf("nodegroup scaling missing: %+v", attrs["scaling_config"])
	}
	if row.Resource.Tags["team"] != "platform" || row.Resource.SourceRecordID != aws.ToString(nodegroup.NodegroupArn) {
		t.Fatalf("nodegroup provenance changed: %+v", row.Resource)
	}
}

func TestEKSNodegroupRecordIdentityFallback(t *testing.T) {
	row, err := eksNodegroupRecord(ekstypes.Nodegroup{
		ClusterName: aws.String("demo"), NodegroupName: aws.String("workers"),
	}, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if row.Resource == nil || row.Resource.ResourceID != "demo/workers" || row.Resource.SourceRecordID != "demo/workers" {
		t.Fatalf("nodegroup fallback identity changed: %+v", row.Resource)
	}
	if _, err := eksNodegroupRecord(ekstypes.Nodegroup{NodegroupName: aws.String("workers")}, "us-east-1"); err == nil {
		t.Fatal("nodegroup without ARN or cluster name was accepted")
	}
}
