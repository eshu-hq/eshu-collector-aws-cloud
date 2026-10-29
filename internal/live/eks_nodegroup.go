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

// eksNodegroupRecord carries the reported managed node group fields from DescribeNodegroup.
func eksNodegroupRecord(nodegroup ekstypes.Nodegroup, region string) (collector.Record, error) {
	arn := strings.TrimSpace(aws.ToString(nodegroup.NodegroupArn))
	name := strings.TrimSpace(aws.ToString(nodegroup.NodegroupName))
	clusterName := strings.TrimSpace(aws.ToString(nodegroup.ClusterName))
	id := arn
	if id == "" && clusterName != "" && name != "" {
		id = clusterName + "/" + name
	}
	if id == "" {
		return collector.Record{}, fmt.Errorf("EKS nodegroup has no source identity")
	}
	roleARN := strings.TrimSpace(aws.ToString(nodegroup.NodeRole))
	result := record(arn, "eks", region, name, "nodegroup")
	result.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "eks", ResourceType: "aws_eks_nodegroup",
		ResourceID: id, ARN: arn, Name: name, State: strings.TrimSpace(string(nodegroup.Status)),
		Tags: eksTags(nodegroup.Tags),
		Attributes: map[string]any{
			"ami_type":        strings.TrimSpace(string(nodegroup.AmiType)),
			"capacity_type":   strings.TrimSpace(string(nodegroup.CapacityType)),
			"cluster_name":    clusterName,
			"instance_types":  append([]string(nil), nodegroup.InstanceTypes...),
			"node_role_arn":   roleARN,
			"release_version": strings.TrimSpace(aws.ToString(nodegroup.ReleaseVersion)),
			"scaling_config":  eksScalingConfig(nodegroup.ScalingConfig),
			"subnets":         append([]string(nil), nodegroup.Subnets...),
			"version":         strings.TrimSpace(aws.ToString(nodegroup.Version)),
		},
		CorrelationAnchors: []string{id, name, roleARN}, SourceRecordID: id,
	}
	return result, nil
}

func eksScalingConfig(config *ekstypes.NodegroupScalingConfig) map[string]any {
	if config == nil {
		return map[string]any{"desired_size": int32(0), "min_size": int32(0), "max_size": int32(0)}
	}
	return map[string]any{
		"desired_size": aws.ToInt32(config.DesiredSize),
		"min_size":     aws.ToInt32(config.MinSize),
		"max_size":     aws.ToInt32(config.MaxSize),
	}
}
