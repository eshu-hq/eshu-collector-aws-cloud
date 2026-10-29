// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// eksClusterRelationships carries role and network edges reported by DescribeCluster.
func eksClusterRelationships(cluster ekstypes.Cluster, region, clusterID, clusterARN string) []collector.LiveRelationship {
	if clusterID == "" {
		return nil
	}
	base := collector.LiveRelationship{
		Region: region, ServiceKind: "eks", SourceResourceID: clusterID, SourceARN: clusterARN,
	}
	var edges []collector.LiveRelationship
	if roleARN := strings.TrimSpace(aws.ToString(cluster.RoleArn)); roleARN != "" {
		edge := base
		edge.RelationshipType = "eks_cluster_uses_iam_role"
		edge.TargetResourceID, edge.TargetARN, edge.TargetType = roleARN, roleARN, "aws_iam_role"
		edge.SourceRecordID = clusterID + "#role#" + roleARN
		edges = append(edges, edge)
	}
	if cluster.ResourcesVpcConfig == nil {
		return edges
	}
	vpc := cluster.ResourcesVpcConfig
	vpcID := strings.TrimSpace(aws.ToString(vpc.VpcId))
	for _, candidate := range vpc.SubnetIds {
		subnetID := strings.TrimSpace(candidate)
		if subnetID == "" {
			continue
		}
		edge := base
		edge.RelationshipType, edge.TargetResourceID, edge.TargetType = "eks_cluster_uses_subnet", subnetID, "aws_ec2_subnet"
		edge.Attributes = map[string]any{"vpc_id": vpcID}
		edge.SourceRecordID = clusterID + "#subnet#" + subnetID
		edges = append(edges, edge)
	}
	groupIDs := append(append([]string(nil), vpc.SecurityGroupIds...), aws.ToString(vpc.ClusterSecurityGroupId))
	seen := make(map[string]struct{}, len(groupIDs))
	for _, candidate := range groupIDs {
		groupID := strings.TrimSpace(candidate)
		if groupID == "" {
			continue
		}
		if _, exists := seen[groupID]; exists {
			continue
		}
		seen[groupID] = struct{}{}
		edge := base
		edge.RelationshipType, edge.TargetResourceID, edge.TargetType = "eks_cluster_uses_security_group", groupID, "aws_ec2_security_group"
		edge.Attributes = map[string]any{"vpc_id": vpcID}
		edge.SourceRecordID = clusterID + "#security-group#" + groupID
		edges = append(edges, edge)
	}
	return edges
}
