// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

func TestEKSClusterRecordRelationships(t *testing.T) {
	arn := "arn:aws:eks:us-east-1:123456789012:cluster/demo"
	role := "arn:aws:iam::123456789012:role/demo"
	cluster := ekstypes.Cluster{
		Arn: aws.String(arn), Name: aws.String("demo"), RoleArn: aws.String(role),
		ResourcesVpcConfig: &ekstypes.VpcConfigResponse{
			VpcId: aws.String("vpc-1"), SubnetIds: []string{"subnet-1", " "},
			SecurityGroupIds: []string{"sg-1", "sg-1"}, ClusterSecurityGroupId: aws.String("sg-2"),
		},
	}
	row, err := eksClusterRecord(cluster, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(row.Relationships) != 4 {
		t.Fatalf("EKS cluster relationship count = %d, want 4: %+v", len(row.Relationships), row.Relationships)
	}
	want := []struct{ kind, target, record string }{
		{"eks_cluster_uses_iam_role", role, arn + "#role#" + role},
		{"eks_cluster_uses_subnet", "subnet-1", arn + "#subnet#subnet-1"},
		{"eks_cluster_uses_security_group", "sg-1", arn + "#security-group#sg-1"},
		{"eks_cluster_uses_security_group", "sg-2", arn + "#security-group#sg-2"},
	}
	for i, edge := range row.Relationships {
		if edge.RelationshipType != want[i].kind || edge.TargetResourceID != want[i].target || edge.SourceRecordID != want[i].record || edge.SourceResourceID != arn || edge.SourceARN != arn {
			t.Fatalf("EKS cluster relationship %d changed: %+v", i, edge)
		}
		observation := relationshipObservation("123456789012", edge)
		if observation.Boundary.AccountID != "123456789012" || observation.Boundary.Region != "us-east-1" {
			t.Fatalf("EKS relationship claim boundary changed: %+v", observation.Boundary)
		}
		observation.Boundary.ScopeID = "scope-123"
		observation.Boundary.GenerationID = "generation-123"
		observation.Boundary.CollectorInstanceID = "collector-123"
		observation.Boundary.ClaimToken = "opaque-claim-token"
		observation.SourceURI = "aws://123456789012"
		fact, err := collector.NewRelationshipFact(observation)
		if err != nil || fact.Kind != collector.AWSKindRelationship {
			t.Fatalf("EKS relationship rejected by typed boundary: %+v, %v", fact, err)
		}
	}
}
