// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

func TestECSServiceRecordPreservesReportedObservation(t *testing.T) {
	arn := "arn:aws:ecs:us-east-1:123456789012:service/prod/web"
	service := awsecstypes.Service{
		ServiceArn: aws.String(arn), ServiceName: aws.String("web"),
		ClusterArn: aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/prod"),
		Status:     aws.String("ACTIVE"), TaskDefinition: aws.String("arn:aws:ecs:us-east-1:123456789012:task-definition/web:4"),
		LaunchType: awsecstypes.LaunchTypeFargate, PlatformVersion: aws.String("1.4.0"),
		DesiredCount: 3, RunningCount: 2, PendingCount: 1,
		LoadBalancers: []awsecstypes.LoadBalancer{{TargetGroupArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web/abc"), ContainerName: aws.String("web"), ContainerPort: aws.Int32(8080)}},
		Tags:          []awsecstypes.Tag{{Key: aws.String(" team "), Value: aws.String("platform")}},
	}
	row := mustECSServiceRecord(t, service, "us-east-1")
	if row.ID != arn || row.Name != "web" {
		t.Fatalf("placeholder identity changed: %+v", row)
	}
	resource := row.Resource
	if resource == nil || resource.ARN != arn || resource.ResourceID != arn || resource.ResourceType != "aws_ecs_service" || resource.Name != "web" || resource.State != "ACTIVE" || resource.SourceRecordID != arn {
		t.Fatalf("typed service identity missing: %+v", resource)
	}
	if resource.Tags["team"] != "platform" || resource.Attributes["cluster_arn"] != aws.ToString(service.ClusterArn) || resource.Attributes["desired_count"] != int32(3) || resource.Attributes["running_count"] != int32(2) || resource.Attributes["pending_count"] != int32(1) || resource.Attributes["launch_type"] != "FARGATE" || resource.Attributes["platform_version"] != "1.4.0" || resource.Attributes["task_definition_arn"] != aws.ToString(service.TaskDefinition) {
		t.Fatalf("reported service metadata changed: %+v", resource)
	}
	balancers, ok := resource.Attributes["load_balancers"].([]map[string]any)
	if !ok || len(balancers) != 1 || balancers[0]["container_name"] != "web" || balancers[0]["container_port"] != int32(8080) || balancers[0]["target_group_arn"] != aws.ToString(service.LoadBalancers[0].TargetGroupArn) {
		t.Fatalf("load balancer metadata changed: %+v", resource.Attributes["load_balancers"])
	}
	if len(resource.CorrelationAnchors) != 3 || resource.CorrelationAnchors[0] != arn || resource.CorrelationAnchors[1] != "web" || resource.CorrelationAnchors[2] != aws.ToString(service.TaskDefinition) {
		t.Fatalf("service anchors changed: %+v", resource.CorrelationAnchors)
	}
}

func TestECSServiceDescribeRequestsTagsAndOmitsMissingBalancer(t *testing.T) {
	input := ecsServiceDescribeInput("cluster", []string{"service"})
	if len(input.Include) != 1 || input.Include[0] != awsecstypes.ServiceFieldTags {
		t.Fatalf("service tags request missing: %+v", input)
	}
	row := mustECSServiceRecord(t, awsecstypes.Service{ServiceArn: aws.String("arn:aws:ecs:us-east-1:123456789012:service/prod/web")}, "us-east-1")
	if balancers, ok := row.Resource.Attributes["load_balancers"].([]map[string]any); !ok || balancers != nil {
		t.Fatalf("absent load balancers invented: %+v", row.Resource.Attributes["load_balancers"])
	}
	if mustECSServiceRecord(t, awsecstypes.Service{}, "us-east-1").Resource != nil {
		t.Fatal("service without ARN got typed identity")
	}
}

func mustECSServiceRecord(t *testing.T, service awsecstypes.Service, region string) collector.Record {
	t.Helper()
	row, err := ecsServiceRecord(service, region)
	if err != nil {
		t.Fatal(err)
	}
	return row
}
