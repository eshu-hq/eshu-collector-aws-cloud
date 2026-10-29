// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/eshu-hq/eshu-sdk/collector/marker"
)

type ecsRoundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip ecsRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestListECSIncludesInactiveServiceDefinitionOnce(t *testing.T) {
	const prefix = "arn:aws:ecs:us-east-1:123456789012:"
	clusterARN := prefix + "cluster/prod"
	inactiveARN := prefix + "task-definition/web:1"
	activeARN := prefix + "task-definition/web:2"
	describeCounts := map[string]int{}
	operations := map[string]int{}
	responses := map[string]any{
		"ListClusters":        map[string]any{"clusterArns": []string{clusterARN}},
		"DescribeClusters":    map[string]any{"clusters": []map[string]any{{"clusterArn": clusterARN, "clusterName": "prod"}}},
		"ListServices":        map[string]any{"serviceArns": []string{prefix + "service/prod/old", prefix + "service/prod/current"}},
		"DescribeServices":    map[string]any{"services": []map[string]any{{"serviceArn": prefix + "service/prod/old", "taskDefinition": inactiveARN}, {"serviceArn": prefix + "service/prod/current", "taskDefinition": activeARN}}},
		"ListTasks":           map[string]any{"taskArns": []string{}},
		"ListTaskDefinitions": map[string]any{"taskDefinitionArns": []string{activeARN}},
	}
	transport := ecsRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		target := request.Header.Get("X-Amz-Target")
		operation := target[strings.LastIndex(target, ".")+1:]
		operations[operation]++
		var payload any
		if operation == "DescribeTaskDefinition" {
			var input struct {
				ARN string `json:"taskDefinition"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				return nil, err
			}
			describeCounts[input.ARN]++
			status := "INACTIVE"
			revision := 1
			if input.ARN == activeARN {
				status = "ACTIVE"
				revision = 2
			}
			payload = map[string]any{"taskDefinition": map[string]any{"taskDefinitionArn": input.ARN, "family": "web", "revision": revision, "status": status, "containerDefinitions": []map[string]any{{"name": "web", "environment": []map[string]any{{"name": "PASSWORD", "value": "raw-ecs-secret-canary"}, {"name": "PLAIN", "value": ""}}, "secrets": []map[string]string{{"name": "db", "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:db"}}}}}}
		} else {
			var ok bool
			payload, ok = responses[operation]
			if !ok {
				return nil, fmt.Errorf("unexpected ECS operation %q", target)
			}
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: request}, nil
	})
	cfg := aws.Config{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}, RetryMaxAttempts: 1}
	records, err := listECS(context.Background(), cfg, testRedactionKey())
	if err != nil {
		t.Fatal(err)
	}
	resourceCounts := map[string]int{}
	states := map[string]string{}
	for _, row := range records {
		if row.Resource != nil && row.Resource.ResourceType == "aws_ecs_task_definition" {
			resourceCounts[row.Resource.ResourceID]++
			states[row.Resource.ResourceID] = row.Resource.State
		}
	}
	if resourceCounts[inactiveARN] != 1 || resourceCounts[activeARN] != 1 || len(resourceCounts) != 2 || states[inactiveARN] != "INACTIVE" {
		t.Fatalf("task definition coverage = %+v, want one active and one service-referenced inactive definition", resourceCounts)
	}
	for _, row := range records {
		if row.Resource == nil || row.Resource.ResourceType != "aws_ecs_task_definition" {
			continue
		}
		containers := row.Resource.Attributes["containers"].([]map[string]any)
		if len(containers) != 1 || containers[0]["name"] != "web" {
			t.Fatalf("ECS container shape: %#v", containers)
		}
		environment := containers[0]["environment"].([]map[string]any)
		for index, name := range []string{"PASSWORD", "PLAIN"} {
			entry := environment[index]
			if len(entry) != 2 || entry["name"] != name {
				t.Fatalf("ECS environment entry: %#v", entry)
			}
			raw, reason := "", "unknown_provider_schema"
			if name == "PASSWORD" {
				raw, reason = "raw-ecs-secret-canary", "known_sensitive_key"
			}
			source := "ecs.task_definition.container.environment." + name
			want := marker.String(raw, reason, source, testRedactionKey())
			value := entry["value"].(map[string]any)
			if len(value) != 4 || value["marker"] != want.Marker || value["reason"] != want.Reason || value["source"] != want.Source || value["ruleset_version"] != awsRedactionRuleset {
				t.Fatalf("ECS marker mismatch: %#v", value)
			}
		}
		secrets := containers[0]["secrets"].([]map[string]string)
		if len(secrets) != 1 || len(secrets[0]) != 2 || secrets[0]["name"] != "db" || secrets[0]["value_from"] != "arn:aws:secretsmanager:us-east-1:123456789012:secret:db" {
			t.Fatalf("ECS secret references: %#v", secrets)
		}
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "raw-ecs-secret-canary") {
		t.Fatal("ECS SDK records contain raw environment value")
	}
	if operations["GetSecretValue"] != 0 || operations["BatchGetSecretValue"] != 0 {
		t.Fatalf("ECS source fetched secret content: %#v", operations)
	}
	if describeCounts[inactiveARN] != 1 || describeCounts[activeARN] != 1 || len(describeCounts) != 2 {
		t.Fatalf("DescribeTaskDefinition calls = %+v, want one per distinct ARN", describeCounts)
	}
}
