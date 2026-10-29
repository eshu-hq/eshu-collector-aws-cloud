// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// eksClusterRecord carries EKS-reported cluster metadata from DescribeCluster.
// IAM OIDC provider enrichment needs a separate read and is not inferred here.
func eksClusterRecord(cluster ekstypes.Cluster, region string) (collector.Record, error) {
	arn := strings.TrimSpace(aws.ToString(cluster.Arn))
	name := strings.TrimSpace(aws.ToString(cluster.Name))
	id := arn
	if id == "" {
		id = name
	}
	if id == "" {
		return collector.Record{}, fmt.Errorf("EKS cluster has no source identity")
	}
	result := record(arn, "eks", region, name, "cluster")
	attrs := map[string]any{
		"created_at":       nil,
		"endpoint":         strings.TrimSpace(aws.ToString(cluster.Endpoint)),
		"oidc_provider":    eksOIDCProvider(cluster.Identity),
		"platform_version": strings.TrimSpace(aws.ToString(cluster.PlatformVersion)),
		"role_arn":         strings.TrimSpace(aws.ToString(cluster.RoleArn)),
		"version":          strings.TrimSpace(aws.ToString(cluster.Version)),
		"vpc_config":       eksVPCConfig(cluster.ResourcesVpcConfig),
	}
	if cluster.CreatedAt != nil && !cluster.CreatedAt.IsZero() {
		attrs["created_at"] = cluster.CreatedAt.UTC()
	}
	result.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "eks", ResourceType: "aws_eks_cluster",
		ResourceID: id, ARN: arn, Name: name, State: strings.TrimSpace(string(cluster.Status)),
		Tags: eksTags(cluster.Tags), Attributes: attrs,
		CorrelationAnchors: []string{arn, name}, SourceRecordID: id,
	}
	result.Relationships = eksClusterRelationships(cluster, region, id, arn)
	return result, nil
}

func eksVPCConfig(config *ekstypes.VpcConfigResponse) map[string]any {
	if config == nil || (aws.ToString(config.VpcId) == "" && len(config.SubnetIds) == 0 && len(config.SecurityGroupIds) == 0 && aws.ToString(config.ClusterSecurityGroupId) == "") {
		return nil
	}
	return map[string]any{
		"cluster_security_group_id": strings.TrimSpace(aws.ToString(config.ClusterSecurityGroupId)),
		"endpoint_private_access":   config.EndpointPrivateAccess,
		"endpoint_public_access":    config.EndpointPublicAccess,
		"public_access_cidrs":       append([]string(nil), config.PublicAccessCidrs...),
		"security_group_ids":        append([]string(nil), config.SecurityGroupIds...),
		"subnet_ids":                append([]string(nil), config.SubnetIds...),
		"vpc_id":                    strings.TrimSpace(aws.ToString(config.VpcId)),
	}
}

func eksTags(tags map[string]string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	result := make(map[string]string, len(tags))
	for key, value := range tags {
		if trimmed := strings.TrimSpace(key); trimmed != "" {
			result[trimmed] = value
		}
	}
	return result
}

// eksOIDCProvider retains only the issuer reported by EKS. A provider ARN,
// thumbprints, and client IDs require the separate IAM lookup.
func eksOIDCProvider(identity *ekstypes.Identity) map[string]any {
	if identity == nil || identity.Oidc == nil {
		return nil
	}
	issuer := strings.TrimSpace(aws.ToString(identity.Oidc.Issuer))
	if issuer == "" {
		return nil
	}
	return map[string]any{
		"arn": "", "client_ids": []string(nil),
		"issuer_url": issuer, "thumbprints": []string(nil),
	}
}
