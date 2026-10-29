// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func TestECSTaskDefinitionRecordRetainsSafeMetadata(t *testing.T) {
	arn := "arn:aws:ecs:us-east-1:123456789012:task-definition/web:4"
	registered := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	definition := awsecstypes.TaskDefinition{
		TaskDefinitionArn: aws.String(arn), Family: aws.String("web"), Revision: 4,
		Status: awsecstypes.TaskDefinitionStatusActive, Cpu: aws.String("256"), Memory: aws.String("512"),
		ExecutionRoleArn: aws.String("execution-role-arn"), TaskRoleArn: aws.String("task-role-arn"),
		NetworkMode: awsecstypes.NetworkModeAwsvpc, RegisteredAt: &registered,
		RequiresCompatibilities: []awsecstypes.Compatibility{awsecstypes.CompatibilityFargate},
		ContainerDefinitions:    []awsecstypes.ContainerDefinition{{Name: aws.String("web"), Environment: []awsecstypes.KeyValuePair{{Name: aws.String("PASSWORD"), Value: aws.String("raw-secret")}}, Secrets: []awsecstypes.Secret{{Name: aws.String("db"), ValueFrom: aws.String("secret-arn")}}}},
	}
	row := ecsTaskDefinitionRecord(arn, definition, []awsecstypes.Tag{{Key: aws.String("team"), Value: aws.String("platform")}}, "us-east-1")
	if row.ID != arn || row.Resource == nil || row.Resource.ResourceID != arn || row.Resource.ResourceType != "aws_ecs_task_definition" || row.Resource.Name != "web" || row.Resource.State != "ACTIVE" || row.Resource.SourceRecordID != arn {
		t.Fatalf("task definition identity: %+v", row)
	}
	if row.Resource.Tags["team"] != "platform" || row.Resource.Attributes["cpu"] != "256" || row.Resource.Attributes["memory"] != "512" || row.Resource.Attributes["revision"] != int32(4) || row.Resource.Attributes["registered_at"] != registered {
		t.Fatalf("task definition metadata: %+v", row.Resource)
	}
	if _, exists := row.Resource.Attributes["containers"]; exists {
		t.Fatalf("unredacted container data emitted: %+v", row.Resource.Attributes["containers"])
	}
	if len(row.Resource.CorrelationAnchors) != 3 || row.Resource.CorrelationAnchors[2] != "web:4" {
		t.Fatalf("task definition anchors: %+v", row.Resource.CorrelationAnchors)
	}
}

func TestECSTaskDefinitionDescribeRequestsTagsAndRejectsMissingARN(t *testing.T) {
	input := ecsTaskDefinitionDescribeInput("definition-arn")
	if len(input.Include) != 1 || input.Include[0] != awsecstypes.TaskDefinitionFieldTags {
		t.Fatalf("tags request missing: %+v", input)
	}
	if ecsTaskDefinitionRecord("", awsecstypes.TaskDefinition{}, nil, "us-east-1").Resource != nil {
		t.Fatal("missing source ARN got typed identity")
	}
	if ecsTaskDefinitionRecord("listed-arn", awsecstypes.TaskDefinition{TaskDefinitionArn: aws.String("other-arn")}, nil, "us-east-1").Resource != nil {
		t.Fatal("mismatched described ARN got typed identity")
	}
}
