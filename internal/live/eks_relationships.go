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

// eksNodegroupRelationships carries the role and subnet edges reported by DescribeNodegroup.
func eksNodegroupRelationships(nodegroup ekstypes.Nodegroup, region, nodegroupID, nodegroupARN string) []collector.LiveRelationship {
	base := collector.LiveRelationship{
		Region: region, ServiceKind: "eks", SourceResourceID: nodegroupID, SourceARN: nodegroupARN,
	}
	var edges []collector.LiveRelationship
	if roleARN := strings.TrimSpace(aws.ToString(nodegroup.NodeRole)); roleARN != "" {
		edge := base
		edge.RelationshipType = "eks_nodegroup_uses_iam_role"
		edge.TargetResourceID, edge.TargetARN, edge.TargetType = roleARN, roleARN, "aws_iam_role"
		edge.SourceRecordID = nodegroupID + "#role#" + roleARN
		edges = append(edges, edge)
	}
	for _, candidate := range nodegroup.Subnets {
		subnetID := strings.TrimSpace(candidate)
		if subnetID == "" {
			continue
		}
		edge := base
		edge.RelationshipType, edge.TargetResourceID, edge.TargetType = "eks_nodegroup_uses_subnet", subnetID, "aws_ec2_subnet"
		edge.SourceRecordID = nodegroupID + "#subnet#" + subnetID
		edges = append(edges, edge)
	}
	return edges
}

// eksAddonRelationships carries the service account role edge reported by DescribeAddon.
func eksAddonRelationships(addon ekstypes.Addon, region, addonID, addonARN string) []collector.LiveRelationship {
	roleARN := strings.TrimSpace(aws.ToString(addon.ServiceAccountRoleArn))
	if roleARN == "" {
		return nil
	}
	return []collector.LiveRelationship{{
		Region: region, ServiceKind: "eks", RelationshipType: "eks_addon_uses_iam_role",
		SourceResourceID: addonID, SourceARN: addonARN,
		TargetResourceID: roleARN, TargetARN: roleARN, TargetType: "aws_iam_role",
		SourceRecordID: addonID + "#role#" + roleARN,
	}}
}

// eksMembershipRelationship joins an observed child to its observed parent cluster.
// A missing or conflicting cluster name leaves membership unasserted.
func eksMembershipRelationship(cluster, child *collector.LiveResource, reportedClusterName string) (collector.LiveRelationship, bool) {
	if cluster == nil || child == nil || cluster.ResourceType != "aws_eks_cluster" ||
		cluster.ServiceKind != "eks" || child.ServiceKind != "eks" || cluster.Region != child.Region ||
		cluster.ResourceID == "" || child.ResourceID == "" ||
		strings.TrimSpace(cluster.Name) == "" || strings.TrimSpace(cluster.Name) != strings.TrimSpace(reportedClusterName) {
		return collector.LiveRelationship{}, false
	}
	kind := ""
	member := ""
	switch child.ResourceType {
	case "aws_eks_nodegroup":
		kind, member = "eks_cluster_has_nodegroup", "nodegroup"
	case "aws_eks_addon":
		kind, member = "eks_cluster_has_addon", "addon"
	default:
		return collector.LiveRelationship{}, false
	}
	return collector.LiveRelationship{
		Region: cluster.Region, ServiceKind: "eks", RelationshipType: kind,
		SourceResourceID: cluster.ResourceID, SourceARN: cluster.ARN,
		TargetResourceID: child.ResourceID, TargetARN: child.ARN, TargetType: child.ResourceType,
		SourceRecordID: cluster.ResourceID + "#" + member + "#" + child.ResourceID,
	}, true
}
