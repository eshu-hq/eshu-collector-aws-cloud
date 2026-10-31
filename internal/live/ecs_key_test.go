// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/eshu-hq/eshu-sdk/collector/marker"
)

func ecsKeyTestConfig() map[string]any {
	return map[string]any{
		"target_scopes":    map[string]any{"account_id": "123456789012"},
		"allowed_regions":  []any{"us-east-1"},
		"allowed_services": []any{"ecs"},
		"source":           map[string]any{"redactionKeyEnv": "ESHU_AWS_REDACTION_KEY"},
	}
}

func TestParseConfigAcceptsFixedRedactionKeyEnv(t *testing.T) {
	parsed, err := ParseConfig(ecsKeyTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.RedactionKeyEnv != "ESHU_AWS_REDACTION_KEY" {
		t.Fatalf("RedactionKeyEnv = %q, want the fixed variable", parsed.RedactionKeyEnv)
	}
}

func TestParseConfigRejectsForeignRedactionKeyEnv(t *testing.T) {
	config := ecsKeyTestConfig()
	config["source"] = map[string]any{"redactionKeyEnv": "SOME_OTHER_VAR"}
	if _, err := ParseConfig(config); err == nil || !strings.Contains(err.Error(), "redactionKeyEnv") {
		t.Fatalf("ParseConfig(foreign key env) error = %v, want redactionKeyEnv failure", err)
	}
}

func TestCollectReportFailsECSTaskDefinitionWithoutKey(t *testing.T) {
	parsed, err := ParseConfig(map[string]any{
		"target_scopes":    map[string]any{"account_id": "123456789012"},
		"allowed_regions":  []any{"us-east-1"},
		"allowed_services": []any{"ecs"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Collector{}).CollectReport(context.Background(), parsed); err == nil || !strings.Contains(err.Error(), "ESHU_AWS_REDACTION_KEY") {
		t.Fatalf("CollectReport(ecs without key) error = %v, want redaction key failure", err)
	}
}

func TestListECSRequiresKeyBeforeAcquisition(t *testing.T) {
	cfg := aws.Config{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, RetryMaxAttempts: 1}
	if _, err := listECS(context.Background(), cfg, marker.Key{}); err == nil {
		t.Fatal("listECS(zero key) error = nil, want failure before source acquisition")
	}
}

func TestRedactECSEnvironmentValueNeverLeaksRaw(t *testing.T) {
	key := ecsParityTestKey(t)
	for _, source := range []string{
		"ecs.task_definition.container.environment.DATABASE_URL",
		"ecs.task_definition.container.environment.LOG_LEVEL",
		"ApiKeyValue",
		"ServiceAccessKeyId",
	} {
		redacted := redactECSEnvironmentValue("raw-secret-material", source, key)
		if redacted["ruleset_version"] != ecsRedactionRuleset {
			t.Fatalf("ruleset_version = %#v, want launch policy", redacted["ruleset_version"])
		}
		if markerText, _ := redacted["marker"].(string); !strings.HasPrefix(markerText, "redacted:hmac-sha256:") {
			t.Fatalf("marker = %#v, want HMAC marker", redacted["marker"])
		}
		if redacted["marker"] == "raw-secret-material" || redacted["source"] == "raw-secret-material" || redacted["reason"] == "raw-secret-material" {
			t.Fatalf("raw material leaked into labels: %#v", redacted)
		}
	}
	sensitive := redactECSEnvironmentValue("v", "ecs.task_definition.container.environment.DATABASE_URL", key)
	if sensitive["reason"] != "known_sensitive_key" {
		t.Fatalf("reason = %#v, want known_sensitive_key", sensitive["reason"])
	}
	plain := redactECSEnvironmentValue("v", "ecs.task_definition.container.environment.LOG_LEVEL", key)
	if plain["reason"] != "unknown_provider_schema" {
		t.Fatalf("reason = %#v, want unknown_provider_schema", plain["reason"])
	}
}

// TestECSSensitiveSourceMirrorsInTreeLaunchPolicy pins reason labels for
// spellings where whole-vs-segment matching could diverge from the in-tree
// launch policy (eshu go/internal/redact/policy.go RuleSet.Classify with
// SchemaUnknown, backed by the identical 37-entry awsSensitiveKeys set).
// Compound keys that merely contain a sensitive word classify unknown on
// both sides: neither whole-normalized nor ./[] segments match, and the
// token-window matcher is CloudFormation-only. Values stay redacted either
// way; only the label must agree.
func TestECSSensitiveSourceMirrorsInTreeLaunchPolicy(t *testing.T) {
	key := ecsParityTestKey(t)
	cases := []struct{ source, want string }{
		{"DATABASE_URL", "known_sensitive_key"},
		{"database-url", "known_sensitive_key"},
		{"config.auth.token", "known_sensitive_key"},
		{"ServiceAccessKeyId", "unknown_provider_schema"},
		{"ApiKeyValue", "unknown_provider_schema"},
		{"config.database_password", "unknown_provider_schema"},
		{"X-Auth-Token", "unknown_provider_schema"},
		{"LOG_LEVEL", "unknown_provider_schema"},
	}
	for _, tc := range cases {
		if got := redactECSEnvironmentValue("v", tc.source, key)["reason"]; got != tc.want {
			t.Errorf("reason(%q) = %#v, want %q (in-tree agreement)", tc.source, got, tc.want)
		}
	}
}
