// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/eshu-hq/eshu-sdk/collector/marker"
)

func TestAWSRedactionUsesLegacyPolicyAndKey(t *testing.T) {
	key, err := marker.NewKey([]byte("test-deployment-key"))
	if err != nil {
		t.Fatal(err)
	}
	got := redactAWSString("raw-canary", "lambda.function.environment.PASSWORD", key)
	want := marker.String("raw-canary", "known_sensitive_key", "lambda.function.environment.PASSWORD", key)
	if got["marker"] != want.Marker || got["reason"] != want.Reason || got["source"] != want.Source || got["ruleset_version"] != "aws-launch-2026-05-14" {
		t.Fatalf("legacy AWS redaction mismatch: %#v", got)
	}
}

func testRedactionKey() marker.Key {
	key, err := marker.NewKey([]byte("test-deployment-key"))
	if err != nil {
		panic(err)
	}
	return key
}

func TestAWSRedactionUnknownNameAndEmptyValue(t *testing.T) {
	key := testRedactionKey()
	got := redactAWSString("", "ecs.task_definition.container.environment.PLAIN", key)
	want := marker.String("", "unknown_provider_schema", "ecs.task_definition.container.environment.PLAIN", key)
	if got["marker"] != want.Marker || got["reason"] != want.Reason || got["source"] != want.Source {
		t.Fatalf("empty ordinary environment marker: %#v", got)
	}
	if got["marker"] == marker.String("nonempty", "unknown_provider_schema", "ecs.task_definition.container.environment.PLAIN", key).Marker {
		t.Fatal("empty and nonempty values share a marker")
	}
}

func TestZeroRedactionKeyStopsBeforeAWSConfig(t *testing.T) {
	called := false
	reader := Collector{LoadConfig: func(context.Context, string) (aws.Config, error) {
		called = true
		return aws.Config{}, nil
	}}
	for _, service := range []string{"lambda", "ecs"} {
		_, err := reader.CollectReport(context.Background(), Config{Services: []string{service}, Regions: []string{"us-east-1"}})
		if err == nil || called {
			t.Fatalf("service %s: err=%v config-called=%t", service, err, called)
		}
	}
}
