// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"strings"
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/marker"
)

func awsTestMarker(t *testing.T, source string) map[string]any {
	t.Helper()
	key, err := marker.NewKey([]byte("synthetic-aws-bridge-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	value := marker.String("raw-secret", "known_sensitive_key", source, key)
	return map[string]any{
		"marker":          value.Marker,
		"reason":          value.Reason,
		"source":          value.Source,
		"ruleset_version": "aws-launch-2026-05-14",
	}
}

func TestResourceFactAdmitsOnlyFactScopedAWSRedaction(t *testing.T) {
	for _, tc := range []struct {
		name, service, resourceType string
		attributes                  map[string]any
	}{
		{
			name: "lambda", service: "lambda", resourceType: "aws_lambda_function",
			attributes: map[string]any{"environment": map[string]any{
				"API_KEY": awsTestMarker(t, "lambda.function.environment.API_KEY"),
			}},
		},
		{
			name: "ecs", service: "ecs", resourceType: "aws_ecs_task_definition",
			attributes: map[string]any{"containers": []any{map[string]any{
				"environment": []any{map[string]any{
					"name": "API_KEY", "value": awsTestMarker(t, "ecs.task_definition.container.environment.API_KEY"),
				}},
				"secrets": []any{map[string]any{
					"name": "db", "value_from": "arn:aws:secretsmanager:us-east-1:123456789012:secret:example",
				}},
			}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observation := resourceParityObservation(t)
			observation.Boundary.ServiceKind = tc.service
			observation.ResourceType = tc.resourceType
			observation.Attributes = tc.attributes
			fact, err := NewResourceFact(observation)
			if err != nil {
				t.Fatalf("marked resource rejected: %v", err)
			}
			encoded, err := json.Marshal(fact.Payload)
			if err != nil || strings.Contains(string(encoded), "raw-secret") {
				t.Fatalf("raw value reached fact payload: error=%v", err)
			}
			if err := sdk.ValidateShareSafeKeys(fact.Payload); err == nil {
				t.Fatal("generic sensitive-key policy was relaxed")
			}
			base := mustCollect(t, "complete.json", testClaim(), testObservedAt(), "")
			result, err := AppendLiveResources(base, []ResourceObservation{observation}, "aws://123456789012", ResourceUse{})
			if err != nil {
				t.Fatalf("claim-bound resource rejected: %v", err)
			}
			if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
				t.Fatalf("SDK rejected claim-bound resource: %v", err)
			}
		})
	}
}

func TestResourceFactRejectsUnsafeAWSRedaction(t *testing.T) {
	for _, tc := range []struct {
		name, service, resourceType string
		attributes                  map[string]any
	}{
		{
			name: "lambda raw", service: "lambda", resourceType: "aws_lambda_function",
			attributes: map[string]any{"environment": map[string]any{"API_KEY": "raw-secret"}},
		},
		{
			name: "lambda wrong source", service: "lambda", resourceType: "aws_lambda_function",
			attributes: map[string]any{"environment": map[string]any{"API_KEY": awsTestMarker(t, "lambda.function.environment.OTHER")}},
		},
		{
			name: "lambda unrelated sensitive", service: "lambda", resourceType: "aws_lambda_function",
			attributes: map[string]any{"environment": map[string]any{"API_KEY": awsTestMarker(t, "lambda.function.environment.API_KEY")}, "password": "raw-secret"},
		},
		{
			name: "lambda wrong service", service: "ecs", resourceType: "aws_lambda_function",
			attributes: map[string]any{"environment": map[string]any{"API_KEY": awsTestMarker(t, "lambda.function.environment.API_KEY")}},
		},
		{
			name: "ecs raw", service: "ecs", resourceType: "aws_ecs_task_definition",
			attributes: map[string]any{"containers": []any{map[string]any{"environment": []any{map[string]any{"name": "API_KEY", "value": "raw-secret"}}}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observation := resourceParityObservation(t)
			observation.Boundary.ServiceKind = tc.service
			observation.ResourceType = tc.resourceType
			observation.Attributes = tc.attributes
			fact, err := NewResourceFact(observation)
			if err == nil || fact.Kind != "" {
				t.Fatalf("unsafe resource admitted: kind=%q error=%v", fact.Kind, err)
			}
			if strings.Contains(err.Error(), "raw-secret") {
				t.Fatalf("error repeated credential: %v", err)
			}
		})
	}
}
