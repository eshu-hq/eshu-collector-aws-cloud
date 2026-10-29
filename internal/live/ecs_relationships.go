// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

// ecsServiceTaskDefinitionRelationship carries the service's reported revision.
func ecsServiceTaskDefinitionRelationship(serviceARN, definitionARN, region string) (collector.LiveRelationship, bool) {
	serviceARN = strings.TrimSpace(serviceARN)
	definitionARN = strings.TrimSpace(definitionARN)
	if serviceARN == "" || definitionARN == "" {
		return collector.LiveRelationship{}, false
	}
	return collector.LiveRelationship{
		Region: region, ServiceKind: "ecs",
		RelationshipType: catalog.RelationshipECSServiceUsesTaskDefinition,
		SourceResourceID: serviceARN, SourceARN: serviceARN,
		TargetResourceID: definitionARN, TargetARN: definitionARN,
		TargetType:     catalog.ResourceTypeECSTaskDefinition,
		SourceRecordID: serviceARN + "#task-definition#" + definitionARN,
	}, true
}

// ecsServiceLoadBalancerRelationships carries each target reported by DescribeServices.
func ecsServiceLoadBalancerRelationships(serviceARN, region string, balancers []awsecstypes.LoadBalancer) ([]collector.LiveRelationship, error) {
	serviceARN = strings.TrimSpace(serviceARN)
	if serviceARN == "" {
		return nil, nil
	}
	var edges []collector.LiveRelationship
	for _, balancer := range balancers {
		targetARN := strings.TrimSpace(aws.ToString(balancer.TargetGroupArn))
		targetID := targetARN
		targetType := "aws_elbv2_target_group"
		if targetID == "" {
			targetID = strings.TrimSpace(aws.ToString(balancer.LoadBalancerName))
			targetType = "aws_elb_load_balancer"
		}
		if targetID == "" {
			return nil, fmt.Errorf("ecs described service has load balancer without target group ARN or load balancer name")
		}
		edges = append(edges, collector.LiveRelationship{
			Region: region, ServiceKind: "ecs",
			RelationshipType: catalog.RelationshipECSServiceTargetsLoadBalancer,
			SourceResourceID: serviceARN, SourceARN: serviceARN,
			TargetResourceID: targetID, TargetARN: targetARN, TargetType: targetType,
			Attributes: map[string]any{
				"container_name": strings.TrimSpace(aws.ToString(balancer.ContainerName)),
				"container_port": aws.ToInt32(balancer.ContainerPort),
			},
			SourceRecordID: serviceARN + "#load-balancer#" + targetID,
		})
	}
	return edges, nil
}

// ecsTaskNetworkInterfaceRelationships carries ENI IDs reported on task attachments.
func ecsTaskNetworkInterfaceRelationships(taskARN, region string, interfaces []map[string]any, ids []string) []collector.LiveRelationship {
	if taskARN == "" {
		return nil
	}
	var edges []collector.LiveRelationship
	for i, id := range ids {
		edges = append(edges, collector.LiveRelationship{
			Region: region, ServiceKind: "ecs",
			RelationshipType: catalog.RelationshipECSTaskUsesNetworkInterface,
			SourceResourceID: taskARN, SourceARN: taskARN,
			TargetResourceID: id, TargetType: catalog.ResourceTypeEC2NetworkInterface,
			Attributes:     interfaces[i],
			SourceRecordID: taskARN + "#network-interface#" + id,
		})
	}
	return edges
}
