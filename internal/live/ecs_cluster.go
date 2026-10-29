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

// ecsClusterDescribeInput requests the tags present in the legacy cluster observation.
func ecsClusterDescribeInput(arn string) *awsecs.DescribeClustersInput {
	return &awsecs.DescribeClustersInput{
		Clusters: []string{arn},
		Include:  []awsecstypes.ClusterField{awsecstypes.ClusterFieldTags},
	}
}

// ecsClusterRecord carries the DescribeClusters observation into a typed resource.
func ecsClusterRecord(cluster awsecstypes.Cluster, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(cluster.ClusterArn))
	name := aws.ToString(cluster.ClusterName)
	row := record(arn, "ecs", region, name, "cluster")
	if arn == "" {
		return row
	}
	row.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "ecs", ResourceType: "aws_ecs_cluster",
		ResourceID: arn, ARN: arn, Name: name, State: aws.ToString(cluster.Status),
		Tags: ecsClusterTags(cluster.Tags),
		Attributes: map[string]any{
			"active_services_count":                cluster.ActiveServicesCount,
			"pending_tasks_count":                  cluster.PendingTasksCount,
			"registered_container_instances_count": cluster.RegisteredContainerInstancesCount,
			"running_tasks_count":                  cluster.RunningTasksCount,
		},
		CorrelationAnchors: []string{arn, strings.TrimSpace(name)}, SourceRecordID: arn,
	}
	return row
}

func ecsClusterTags(tags []awsecstypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	mapped := make(map[string]string, len(tags))
	for _, tag := range tags {
		key := strings.TrimSpace(aws.ToString(tag.Key))
		if key != "" {
			mapped[key] = aws.ToString(tag.Value)
		}
	}
	return mapped
}
