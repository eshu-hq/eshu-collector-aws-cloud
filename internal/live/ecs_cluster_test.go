// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func TestECSClusterRecordPreservesReportedObservation(t *testing.T) {
	cluster := awsecstypes.Cluster{
		ClusterArn:  aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/prod"),
		ClusterName: aws.String("prod"), Status: aws.String("ACTIVE"),
		ActiveServicesCount: 2, PendingTasksCount: 0,
		RegisteredContainerInstancesCount: 3, RunningTasksCount: 4,
		Tags: []awsecstypes.Tag{{Key: aws.String(" team "), Value: aws.String("platform")}},
	}
	row := ecsClusterRecord(cluster, "us-east-1")
	if row.ID != aws.ToString(cluster.ClusterArn) || row.Name != "prod" {
		t.Fatalf("placeholder identity changed: %+v", row)
	}
	resource := row.Resource
	if resource == nil || resource.ARN != row.ID || resource.ResourceID != row.ID || resource.ResourceType != "aws_ecs_cluster" || resource.Name != "prod" || resource.State != "ACTIVE" {
		t.Fatalf("typed cluster identity missing: %+v", resource)
	}
	if resource.Tags["team"] != "platform" || resource.Attributes["active_services_count"] != int32(2) || resource.Attributes["pending_tasks_count"] != int32(0) || resource.Attributes["registered_container_instances_count"] != int32(3) || resource.Attributes["running_tasks_count"] != int32(4) {
		t.Fatalf("reported cluster metadata changed: %+v", resource)
	}
	if len(resource.CorrelationAnchors) != 2 || resource.CorrelationAnchors[0] != row.ID || resource.CorrelationAnchors[1] != "prod" || resource.SourceRecordID != row.ID {
		t.Fatalf("cluster provenance changed: %+v", resource)
	}
}

func TestECSClusterDescribeRequestsTags(t *testing.T) {
	input := ecsClusterDescribeInput("arn:aws:ecs:us-east-1:123456789012:cluster/prod")
	if len(input.Clusters) != 1 || input.Clusters[0] == "" || len(input.Include) != 1 || input.Include[0] != awsecstypes.ClusterFieldTags {
		t.Fatalf("cluster tag request missing: %+v", input)
	}
}
