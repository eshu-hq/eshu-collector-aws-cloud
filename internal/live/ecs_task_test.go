// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func TestECSTaskRecordPreservesReportedObservation(t *testing.T) {
	arn := "arn:aws:ecs:us-east-1:123456789012:task/prod/abc"
	started := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	task := awsecstypes.Task{
		TaskArn: aws.String(arn), ClusterArn: aws.String("cluster-arn"), TaskDefinitionArn: aws.String("definition-arn"),
		LastStatus: aws.String("RUNNING"), DesiredStatus: aws.String("RUNNING"), LaunchType: awsecstypes.LaunchTypeFargate,
		Group: aws.String("service:web"), StartedAt: &started,
		Containers:  []awsecstypes.Container{{Name: aws.String("web"), Image: aws.String("example/image:tag"), ImageDigest: aws.String("sha256:abc"), RuntimeId: aws.String("runtime")}},
		Attachments: []awsecstypes.Attachment{{Type: aws.String("ElasticNetworkInterface"), Details: []awsecstypes.KeyValuePair{{Name: aws.String("networkInterfaceId"), Value: aws.String("eni-123")}, {Name: aws.String("subnetId"), Value: aws.String("subnet-123")}}}},
	}
	row := ecsTaskRecord(task, "us-east-1")
	if row.ID != arn || row.Name != "abc" {
		t.Fatalf("placeholder identity changed: %+v", row)
	}
	resource := row.Resource
	if resource == nil || resource.ResourceID != arn || resource.ARN != arn || resource.ResourceType != "aws_ecs_task" || resource.Name != arn || resource.State != "RUNNING" || resource.SourceRecordID != arn {
		t.Fatalf("typed task identity: %+v", resource)
	}
	if resource.Attributes["cluster_arn"] != "cluster-arn" || resource.Attributes["desired_status"] != "RUNNING" || resource.Attributes["group"] != "service:web" || resource.Attributes["launch_type"] != "FARGATE" || resource.Attributes["task_definition_arn"] != "definition-arn" || resource.Attributes["started_at"] != started {
		t.Fatalf("task attributes: %+v", resource.Attributes)
	}
	containers, ok := resource.Attributes["containers"].([]map[string]string)
	if !ok || len(containers) != 1 || containers[0]["image_digest"] != "sha256:abc" {
		t.Fatalf("task containers: %+v", resource.Attributes["containers"])
	}
	interfaces, ok := resource.Attributes["network_interfaces"].([]map[string]any)
	if !ok || len(interfaces) != 1 || interfaces[0]["network_interface_id"] != "eni-123" || interfaces[0]["subnet_id"] != "subnet-123" {
		t.Fatalf("task network interfaces: %+v", resource.Attributes["network_interfaces"])
	}
	if len(resource.CorrelationAnchors) != 3 || resource.CorrelationAnchors[0] != arn || resource.CorrelationAnchors[1] != "definition-arn" || resource.CorrelationAnchors[2] != "eni-123" {
		t.Fatalf("task anchors: %+v", resource.CorrelationAnchors)
	}
}

func TestECSTaskRecordOmitsUnknownsAndRejectsMissingARN(t *testing.T) {
	row := ecsTaskRecord(awsecstypes.Task{TaskArn: aws.String("arn:aws:ecs:us-east-1:123456789012:task/prod/abc")}, "us-east-1")
	if row.Resource.Attributes["started_at"] != nil {
		t.Fatalf("unknown start time invented: %+v", row.Resource.Attributes["started_at"])
	}
	if ecsTaskRecord(awsecstypes.Task{}, "us-east-1").Resource != nil {
		t.Fatal("missing ARN got typed identity")
	}
}

func TestECSTaskNetworkInterfaceKeepsFirstReportedDetail(t *testing.T) {
	attachments := []awsecstypes.Attachment{{
		Type: aws.String("ElasticNetworkInterface"),
		Details: []awsecstypes.KeyValuePair{
			{Name: aws.String("networkInterfaceId"), Value: aws.String("eni-first")},
			{Name: aws.String("networkInterfaceId"), Value: aws.String("eni-last")},
			{Name: aws.String("subnetId"), Value: aws.String("subnet-first")},
			{Name: aws.String("subnetId"), Value: aws.String("subnet-last")},
		},
	}}
	interfaces, ids := ecsTaskNetworkInterfaces(attachments)
	if len(interfaces) != 1 || interfaces[0]["network_interface_id"] != "eni-first" || interfaces[0]["subnet_id"] != "subnet-first" || len(ids) != 1 || ids[0] != "eni-first" {
		t.Fatalf("duplicate attachment details changed first reported value: interfaces=%+v ids=%+v", interfaces, ids)
	}
}
