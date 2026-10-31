// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// TestZZECSParityOracle re-executes the deferred ECS relation mapping through
// an independent in-test implementation (hand-derived from the in-tree
// scanner semantics) and requires byte-identical JSON for the resource
// attributes and every relationship. Marker digests are recomputed here with
// stdlib HMAC framing, never through the implementation's marker call path.
func TestZZECSParityOracle(t *testing.T) {
	key := ecsParityTestKey(t)
	arn, definition := ecsParityDefinition()
	row, err := ecsTaskDefinitionRecord(arn, definition, nil, "us-east-1", key)
	if err != nil {
		t.Fatal(err)
	}
	oracleAttributes := map[string]any{
		"containers": []map[string]any{
			{
				"environment": []map[string]any{
					{"name": "DATABASE_URL", "value": zzMarker(t, "postgres://user:password@example.internal/app", "known_sensitive_key", "ecs.task_definition.container.environment.DATABASE_URL")},
					{"name": "LOG_LEVEL", "value": zzMarker(t, "info", "unknown_provider_schema", "ecs.task_definition.container.environment.LOG_LEVEL")},
				},
				"essential":  true,
				"image":      "example.com/web:prod",
				"name":       "web",
				"references": []map[string]string{{"name": "API_TOKEN", "value_from": "arn:aws:secretsmanager:us-east-1:123456789012:secret:api-token"}},
			},
			{
				"environment": []map[string]any{
					{"name": "PORT", "value": zzMarker(t, "8080", "unknown_provider_schema", "ecs.task_definition.container.environment.PORT")},
				},
				"essential": false,
				"image":     "example.com/web:prod",
				"name":      "sidecar",
			},
		},
	}
	oracleRelationships := []map[string]any{
		{
			"attributes":         map[string]any{"container_names": []string{"web", "sidecar"}},
			"region":             "us-east-1",
			"relationship_type":  "ecs_task_definition_uses_image",
			"service_kind":       "ecs",
			"source_arn":         arn,
			"source_record_id":   arn + "#container-image#example.com/web:prod",
			"source_resource_id": arn,
			"target_arn":         "",
			"target_resource_id": "example.com/web:prod",
			"target_type":        "container_image",
		},
	}
	zzRequireByteIdenticalJSON(t, "task definition containers", row.Resource.Attributes["containers"], oracleAttributes["containers"])
	gotEdges := make([]map[string]any, 0, len(row.Relationships))
	for _, edge := range row.Relationships {
		gotEdges = append(gotEdges, map[string]any{
			"attributes":         edge.Attributes,
			"region":             edge.Region,
			"relationship_type":  edge.RelationshipType,
			"service_kind":       edge.ServiceKind,
			"source_arn":         edge.SourceARN,
			"source_record_id":   edge.SourceRecordID,
			"source_resource_id": edge.SourceResourceID,
			"target_arn":         edge.TargetARN,
			"target_resource_id": edge.TargetResourceID,
			"target_type":        edge.TargetType,
		})
	}
	zzRequireByteIdenticalJSON(t, "task definition image relationships", gotEdges, oracleRelationships)

	serviceARN := "arn:aws:ecs:us-east-1:123456789012:service/prod/web"
	targetARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web/abc"
	serviceRow, err := ecsServiceRecord(awsecstypes.Service{
		ServiceArn: aws.String(serviceARN),
		LoadBalancers: []awsecstypes.LoadBalancer{
			{TargetGroupArn: aws.String(targetARN), ContainerName: aws.String("web"), ContainerPort: aws.Int32(8080)},
		},
	}, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	oracleLB := []map[string]any{
		{
			"attributes":         map[string]any{"container_name": "web", "container_port": int32(8080)},
			"region":             "us-east-1",
			"relationship_type":  "ecs_service_targets_load_balancer",
			"service_kind":       "ecs",
			"source_arn":         serviceARN,
			"source_record_id":   serviceARN + "#load-balancer#" + targetARN,
			"source_resource_id": serviceARN,
			"target_arn":         targetARN,
			"target_resource_id": targetARN,
			"target_type":        "aws_elbv2_target_group",
		},
	}
	gotLB := make([]map[string]any, 0, len(serviceRow.Relationships))
	for _, edge := range serviceRow.Relationships {
		gotLB = append(gotLB, map[string]any{
			"attributes":         edge.Attributes,
			"region":             edge.Region,
			"relationship_type":  edge.RelationshipType,
			"service_kind":       edge.ServiceKind,
			"source_arn":         edge.SourceARN,
			"source_record_id":   edge.SourceRecordID,
			"source_resource_id": edge.SourceResourceID,
			"target_arn":         edge.TargetARN,
			"target_resource_id": edge.TargetResourceID,
			"target_type":        edge.TargetType,
		})
	}
	zzRequireByteIdenticalJSON(t, "service load balancer relationships", gotLB, oracleLB)
}

// zzMarker recomputes the SDK marker digest framing (redact.v1 length-prefixed
// HMAC-SHA256 over reason, source, raw) with stdlib primitives only.
func zzMarker(t *testing.T, raw, reason, source string) map[string]any {
	t.Helper()
	mac := hmac.New(sha256.New, []byte("lane0-ecs-parity-test-key"))
	for _, field := range []string{"redact.v1", reason, source, raw} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		if _, err := mac.Write(length[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := mac.Write([]byte(field)); err != nil {
			t.Fatal(err)
		}
	}
	return map[string]any{
		"marker":          "redacted:hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)),
		"reason":          reason,
		"source":          source,
		"ruleset_version": "aws-launch-2026-05-14",
	}
}

func zzRequireByteIdenticalJSON(t *testing.T, name string, got, want any) {
	t.Helper()
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("%s differs from oracle:\n got: %s\nwant: %s", name, gotJSON, wantJSON)
	}
}
