// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-sdk/collector/marker"
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
	row, err := ecsTaskDefinitionRecord(arn, definition, []awsecstypes.Tag{{Key: aws.String("team"), Value: aws.String("platform")}}, "us-east-1", ecsParityTestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if row.ID != arn || row.Resource == nil || row.Resource.ResourceID != arn || row.Resource.ResourceType != "aws_ecs_task_definition" || row.Resource.Name != "web" || row.Resource.State != "ACTIVE" || row.Resource.SourceRecordID != arn {
		t.Fatalf("task definition identity: %+v", row)
	}
	if row.Resource.Tags["team"] != "platform" || row.Resource.Attributes["cpu"] != "256" || row.Resource.Attributes["memory"] != "512" || row.Resource.Attributes["revision"] != int32(4) || row.Resource.Attributes["registered_at"] != registered {
		t.Fatalf("task definition metadata: %+v", row.Resource)
	}
	containers, ok := row.Resource.Attributes["containers"].([]map[string]any)
	if !ok || len(containers) != 1 {
		t.Fatalf("containers = %#v, want one redacted container map", row.Resource.Attributes["containers"])
	}
	environment, ok := containers[0]["environment"].([]map[string]any)
	if !ok || len(environment) != 1 {
		t.Fatalf("environment = %#v, want one redacted entry", containers[0]["environment"])
	}
	redacted, ok := environment[0]["value"].(map[string]any)
	if !ok {
		t.Fatalf("environment value = %#v, want marker map, never the raw secret", environment[0]["value"])
	}
	markerText, ok := redacted["marker"].(string)
	if !ok || !strings.HasPrefix(markerText, "redacted:hmac-sha256:") {
		t.Fatalf("environment marker = %#v, want HMAC marker", redacted["marker"])
	}
	if redacted["reason"] != "known_sensitive_key" || redacted["ruleset_version"] != "aws-launch-2026-05-14" {
		t.Fatalf("environment classification = %#v, want known_sensitive_key + launch ruleset", redacted)
	}
	refs, ok := containers[0]["references"].([]map[string]string)
	if !ok || len(refs) != 1 || refs[0]["value_from"] != "secret-arn" {
		t.Fatalf("secret reference changed: %#v", containers[0]["references"])
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
	if row, err := ecsTaskDefinitionRecord("", awsecstypes.TaskDefinition{}, nil, "us-east-1", ecsParityTestKey(t)); err != nil || row.Resource != nil {
		t.Fatal("missing source ARN got typed identity")
	}
	if row, err := ecsTaskDefinitionRecord("listed-arn", awsecstypes.TaskDefinition{TaskDefinitionArn: aws.String("other-arn")}, nil, "us-east-1", ecsParityTestKey(t)); err != nil || row.Resource != nil {
		t.Fatal("mismatched described ARN got typed identity")
	}
	if _, err := ecsTaskDefinitionRecord("listed-arn", awsecstypes.TaskDefinition{TaskDefinitionArn: aws.String("listed-arn")}, nil, "us-east-1", marker.Key{}); err == nil {
		t.Fatal("task definition without redaction key got redacted containers")
	}
}

// TestECSTaskDefinitionSecretsBearingRecordPassesResourceFactSeam proves the
// renamed references key traverses the production emission seam: a
// secrets-bearing task definition converts to a valid resource fact, while
// the legacy "secrets" key shape is rejected by the same seam.
func TestECSTaskDefinitionSecretsBearingRecordPassesResourceFactSeam(t *testing.T) {
	arn, definition := ecsParityDefinition()
	row, err := ecsTaskDefinitionRecord(arn, definition, nil, "us-east-1", ecsParityTestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	observation := resourceObservation("123456789012", row.Resource)
	observation.Boundary.ScopeID = "aws:123456789012:us-east-1"
	observation.Boundary.GenerationID = "aws:123456789012:us-east-1:parity:1"
	observation.Boundary.CollectorInstanceID = "aws-parity-ecs"
	observation.Boundary.FencingToken = 7
	observation.SourceURI = "aws:ecs:us-east-1:parity"
	if _, err := collector.NewResourceFact(observation); err != nil {
		t.Fatalf("references-keyed task definition rejected by seam: %v", err)
	}
	containers, ok := observation.Attributes["containers"].([]map[string]any)
	if !ok || len(containers) == 0 {
		t.Fatalf("containers = %#v, want container maps", observation.Attributes["containers"])
	}
	web := containers[0]
	web["secrets"] = web["references"]
	delete(web, "references")
	if _, err := collector.NewResourceFact(observation); err == nil {
		t.Fatal("legacy secrets-keyed task definition passed the seam")
	}
}
