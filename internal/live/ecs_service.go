// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	awsecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// ecsServiceDescribeInput requests the tags included in the legacy service observation.
func ecsServiceDescribeInput(clusterARN string, serviceARNs []string) *awsecs.DescribeServicesInput {
	return &awsecs.DescribeServicesInput{
		Cluster: aws.String(clusterARN), Services: serviceARNs,
		Include: []awsecstypes.ServiceField{awsecstypes.ServiceFieldTags},
	}
}

// ecsServiceRecord carries reported DescribeServices metadata into a typed
// resource. Load-balancer bindings become service-to-target edges; a binding
// that reports no target fails the record instead of dropping the exposure.
func ecsServiceRecord(service awsecstypes.Service, region string) (collector.Record, error) {
	arn := strings.TrimSpace(aws.ToString(service.ServiceArn))
	name := aws.ToString(service.ServiceName)
	row := record(arn, "ecs", region, name, "service")
	if arn == "" {
		return row, nil
	}
	taskDefinitionARN := strings.TrimSpace(aws.ToString(service.TaskDefinition))
	row.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "ecs", ResourceType: "aws_ecs_service",
		ResourceID: arn, ARN: arn, Name: name, State: aws.ToString(service.Status),
		Tags: ecsClusterTags(service.Tags),
		Attributes: map[string]any{
			"cluster_arn":         strings.TrimSpace(aws.ToString(service.ClusterArn)),
			"desired_count":       service.DesiredCount,
			"launch_type":         strings.TrimSpace(string(service.LaunchType)),
			"load_balancers":      ecsServiceLoadBalancers(service.LoadBalancers),
			"pending_count":       service.PendingCount,
			"platform_version":    strings.TrimSpace(aws.ToString(service.PlatformVersion)),
			"running_count":       service.RunningCount,
			"task_definition_arn": taskDefinitionARN,
		},
		CorrelationAnchors: []string{arn, strings.TrimSpace(name), taskDefinitionARN}, SourceRecordID: arn,
	}
	if edge, ok := ecsServiceTaskDefinitionRelationship(arn, taskDefinitionARN, region); ok {
		row.Relationship = &edge
	}
	var err error
	row.Relationships, err = ecsServiceLoadBalancerRelationships(arn, region, service.LoadBalancers)
	if err != nil {
		return collector.Record{}, err
	}
	return row, nil
}

func ecsServiceLoadBalancers(loadBalancers []awsecstypes.LoadBalancer) []map[string]any {
	if len(loadBalancers) == 0 {
		return nil
	}
	mapped := make([]map[string]any, 0, len(loadBalancers))
	for _, loadBalancer := range loadBalancers {
		mapped = append(mapped, map[string]any{
			"container_name":     strings.TrimSpace(aws.ToString(loadBalancer.ContainerName)),
			"container_port":     aws.ToInt32(loadBalancer.ContainerPort),
			"load_balancer_name": strings.TrimSpace(aws.ToString(loadBalancer.LoadBalancerName)),
			"target_group_arn":   strings.TrimSpace(aws.ToString(loadBalancer.TargetGroupArn)),
		})
	}
	return mapped
}
