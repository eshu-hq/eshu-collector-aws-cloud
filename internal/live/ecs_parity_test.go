// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	"github.com/eshu-hq/eshu-sdk/collector/marker"
)

func ecsParityTestKey(t *testing.T) marker.Key {
	t.Helper()
	key, err := marker.NewKey([]byte("lane0-ecs-parity-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func ecsParityDefinition() (string, awsecstypes.TaskDefinition) {
	arn := "arn:aws:ecs:us-east-1:123456789012:task-definition/web:4"
	return arn, awsecstypes.TaskDefinition{
		TaskDefinitionArn: aws.String(arn), Family: aws.String("web"), Revision: 4,
		Status: awsecstypes.TaskDefinitionStatusActive,
		ContainerDefinitions: []awsecstypes.ContainerDefinition{
			{
				Name: aws.String("web"), Image: aws.String("example.com/web:prod"), Essential: aws.Bool(true),
				Environment: []awsecstypes.KeyValuePair{
					{Name: aws.String("DATABASE_URL"), Value: aws.String("postgres://user:password@example.internal/app")},
					{Name: aws.String("LOG_LEVEL"), Value: aws.String("info")},
				},
				Secrets: []awsecstypes.Secret{{Name: aws.String("API_TOKEN"), ValueFrom: aws.String("arn:aws:secretsmanager:us-east-1:123456789012:secret:api-token")}},
			},
			{
				Name: aws.String("sidecar"), Image: aws.String("example.com/web:prod"),
				Environment: []awsecstypes.KeyValuePair{{Name: aws.String("PORT"), Value: aws.String("8080")}},
			},
		},
	}
}

func TestECSTaskDefinitionContainersRedactEnvironmentValues(t *testing.T) {
	arn, definition := ecsParityDefinition()
	row, err := ecsTaskDefinitionRecord(arn, definition, nil, "us-east-1", ecsParityTestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	containers, ok := row.Resource.Attributes["containers"].([]map[string]any)
	if !ok || len(containers) != 2 {
		t.Fatalf("containers = %#v, want two container maps", row.Resource.Attributes["containers"])
	}
	web := containers[0]
	if web["name"] != "web" || web["image"] != "example.com/web:prod" || web["essential"] != true {
		t.Fatalf("container identity changed: %#v", web)
	}
	environment, ok := web["environment"].([]map[string]any)
	if !ok || len(environment) != 2 {
		t.Fatalf("environment = %#v, want two entries", web["environment"])
	}
	if environment[0]["name"] != "DATABASE_URL" {
		t.Fatalf("environment name changed: %#v", environment[0])
	}
	sensitive, ok := environment[0]["value"].(map[string]any)
	if !ok {
		t.Fatalf("sensitive value = %#v, want marker map", environment[0]["value"])
	}
	markerText, ok := sensitive["marker"].(string)
	if !ok || !strings.HasPrefix(markerText, "redacted:hmac-sha256:") {
		t.Fatalf("sensitive marker = %#v, want HMAC marker", sensitive["marker"])
	}
	if sensitive["reason"] != "known_sensitive_key" || sensitive["ruleset_version"] != "aws-launch-2026-05-14" {
		t.Fatalf("sensitive classification = %#v, want known_sensitive_key + launch ruleset", sensitive)
	}
	plain, ok := environment[1]["value"].(map[string]any)
	if !ok {
		t.Fatalf("plain value = %#v, want marker map", environment[1]["value"])
	}
	if plain["reason"] != "unknown_provider_schema" {
		t.Fatalf("plain reason = %#v, want unknown_provider_schema", plain["reason"])
	}
	refs, ok := web["references"].([]map[string]string)
	if !ok || len(refs) != 1 || refs[0]["name"] != "API_TOKEN" || refs[0]["value_from"] != "arn:aws:secretsmanager:us-east-1:123456789012:secret:api-token" {
		t.Fatalf("secret reference changed: %#v", web["references"])
	}
	encoded, err := json.Marshal(row.Resource.Attributes)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"postgres://user:password@example.internal/app", "api-token-secret-value"} {
		if strings.Contains(string(encoded), raw) {
			t.Fatalf("raw secret material leaked into attributes: %q", raw)
		}
	}
}

func TestECSTaskDefinitionContainersOmitAbsentSections(t *testing.T) {
	arn := "arn:aws:ecs:us-east-1:123456789012:task-definition/plain:1"
	definition := awsecstypes.TaskDefinition{
		TaskDefinitionArn: aws.String(arn), Family: aws.String("plain"), Revision: 1,
		Status:               awsecstypes.TaskDefinitionStatusActive,
		ContainerDefinitions: []awsecstypes.ContainerDefinition{{Name: aws.String("plain"), Image: aws.String("example.com/plain:1")}},
	}
	row, err := ecsTaskDefinitionRecord(arn, definition, nil, "us-east-1", ecsParityTestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	containers, ok := row.Resource.Attributes["containers"].([]map[string]any)
	if !ok || len(containers) != 1 {
		t.Fatalf("containers = %#v, want one container map", row.Resource.Attributes["containers"])
	}
	if _, exists := containers[0]["environment"]; exists {
		t.Fatalf("absent environment invented: %#v", containers[0])
	}
	if _, exists := containers[0]["references"]; exists {
		t.Fatalf("absent secret references invented: %#v", containers[0])
	}
}

func TestECSTaskDefinitionRecordRequiresRedactionKey(t *testing.T) {
	arn, definition := ecsParityDefinition()
	if _, err := ecsTaskDefinitionRecord(arn, definition, nil, "us-east-1", marker.Key{}); err == nil {
		t.Fatal("task definition without redaction key got redacted containers")
	}
}

func TestECSTaskDefinitionImageRelationshipsAggregateByImage(t *testing.T) {
	arn, definition := ecsParityDefinition()
	row, err := ecsTaskDefinitionRecord(arn, definition, nil, "us-east-1", ecsParityTestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(row.Relationships) != 1 {
		t.Fatalf("image relationships = %+v, want one aggregated edge", row.Relationships)
	}
	edge := row.Relationships[0]
	if edge.RelationshipType != catalog.RelationshipECSTaskDefinitionUsesImage || edge.SourceResourceID != arn || edge.SourceARN != arn || edge.TargetResourceID != "example.com/web:prod" || edge.TargetType != "container_image" || edge.SourceRecordID != arn+"#container-image#example.com/web:prod" || edge.Region != "us-east-1" || edge.ServiceKind != "ecs" {
		t.Fatalf("image relationship changed: %+v", edge)
	}
	names, ok := edge.Attributes["container_names"].([]string)
	if !ok || len(names) != 2 || names[0] != "web" || names[1] != "sidecar" {
		t.Fatalf("container_names = %#v, want web and sidecar", edge.Attributes["container_names"])
	}
	observed := relationshipObservation("123456789012", edge)
	if observed.Boundary.AccountID != "123456789012" || observed.Boundary.Region != "us-east-1" || observed.Boundary.ServiceKind != "ecs" {
		t.Fatalf("image relationship lost claim binding: %+v", observed.Boundary)
	}
}

func TestECSTaskDefinitionSkipsBlankImageRelationships(t *testing.T) {
	arn := "arn:aws:ecs:us-east-1:123456789012:task-definition/blank:1"
	definition := awsecstypes.TaskDefinition{
		TaskDefinitionArn: aws.String(arn), Family: aws.String("blank"), Revision: 1,
		Status:               awsecstypes.TaskDefinitionStatusActive,
		ContainerDefinitions: []awsecstypes.ContainerDefinition{{Name: aws.String("blank")}},
	}
	row, err := ecsTaskDefinitionRecord(arn, definition, nil, "us-east-1", ecsParityTestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(row.Relationships) != 0 {
		t.Fatalf("invented image relationship: %+v", row.Relationships)
	}
}

func TestECSServiceLoadBalancerRelationshipsMatchLegacy(t *testing.T) {
	serviceARN := "arn:aws:ecs:us-east-1:123456789012:service/prod/web"
	targetARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web/abc"
	row, err := ecsServiceRecord(awsecstypes.Service{
		ServiceArn: aws.String(serviceARN),
		LoadBalancers: []awsecstypes.LoadBalancer{
			{TargetGroupArn: aws.String(" " + targetARN + " "), LoadBalancerName: aws.String("ignored"), ContainerName: aws.String(" web "), ContainerPort: aws.Int32(8080)},
			{LoadBalancerName: aws.String(" classic "), ContainerName: aws.String("api"), ContainerPort: aws.Int32(80)},
		},
	}, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(row.Relationships) != 2 {
		t.Fatalf("load balancer relationships = %+v, want two", row.Relationships)
	}
	for i, want := range []struct{ id, arn, kind, record string }{
		{targetARN, targetARN, catalog.ResourceTypeELBv2TargetGroup, serviceARN + "#load-balancer#" + targetARN},
		{"classic", "", catalog.ResourceTypeELBLoadBalancer, serviceARN + "#load-balancer#classic"},
	} {
		edge := row.Relationships[i]
		if edge.RelationshipType != catalog.RelationshipECSServiceTargetsLoadBalancer || edge.SourceResourceID != serviceARN || edge.SourceARN != serviceARN || edge.TargetResourceID != want.id || edge.TargetARN != want.arn || edge.TargetType != want.kind || edge.SourceRecordID != want.record || edge.Region != "us-east-1" || edge.ServiceKind != "ecs" {
			t.Fatalf("load balancer relationship %d changed: %+v", i, edge)
		}
		if edge.Attributes["container_port"] != []int32{8080, 80}[i] || edge.Attributes["container_name"] != []string{"web", "api"}[i] {
			t.Fatalf("load balancer attributes %d changed: %+v", i, edge.Attributes)
		}
		observed := relationshipObservation("123456789012", edge)
		if observed.Boundary.AccountID != "123456789012" || observed.Boundary.Region != "us-east-1" || observed.Boundary.ServiceKind != "ecs" {
			t.Fatalf("load balancer relationship lost claim binding: %+v", observed.Boundary)
		}
	}
}

func TestECSServiceRecordFailsMalformedLoadBalancer(t *testing.T) {
	if _, err := ecsServiceRecord(awsecstypes.Service{
		ServiceArn:    aws.String("arn:aws:ecs:us-east-1:123456789012:service/prod/web"),
		LoadBalancers: []awsecstypes.LoadBalancer{{ContainerName: aws.String("web"), ContainerPort: aws.Int32(80)}},
	}, "us-east-1"); err == nil {
		t.Fatal("service with targetless load balancer got a record")
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
