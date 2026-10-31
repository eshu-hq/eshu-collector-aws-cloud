// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/eshu-hq/eshu-sdk/collector/marker"
)

// TestECSSensitiveKeysMatchVendoredInTreeList diffs the satellite
// ecsSensitiveKeys membership against the vendored in-tree awsSensitiveKeys
// list, so cross-repo agreement is an in-repo artifact rather than a comment
// claim. Equal length plus every vendored key present proves set equality.
//
// Provenance: testdata/intree-aws-sensitive-keys.txt holds the sorted quoted
// entries of the awsSensitiveKeys slice in eshu-hq/eshu
// go/internal/collector/awscloud/redaction.go at commit b0371c05d5, one key
// per line. Regenerate by extracting that slice's quoted entries, sorting,
// and writing one per line; the test fails on any drift either direction.
func TestECSSensitiveKeysMatchVendoredInTreeList(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../../testdata/intree-aws-sensitive-keys.txt")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			want = append(want, line)
		}
	}
	if len(want) != len(ecsSensitiveKeys) {
		t.Fatalf("vendored in-tree keys = %d, ecsSensitiveKeys = %d", len(want), len(ecsSensitiveKeys))
	}
	for _, key := range want {
		if _, ok := ecsSensitiveKeys[key]; !ok {
			t.Errorf("vendored in-tree key %q missing from ecsSensitiveKeys", key)
		}
	}
}

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
		markerText, ok := redacted["marker"].(string)
		if !ok || !strings.HasPrefix(markerText, "redacted:hmac-sha256:") {
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

// TestECSSensitiveSourceLocalLabels pins reason labels for tricky key
// spellings under this package's own matching rule (whole-normalized, then
// ./[] segments). The 37-entry membership was hand-compared against the
// in-tree awsSensitiveKeys list (eshu go/internal/collector/awscloud/
// redaction.go) and is diffed by TestECSSensitiveKeysMatchVendoredInTreeList
// below against the vendored copy in testdata/intree-aws-sensitive-keys.txt.
// The normalizer plus the segment rule mirror eshu go/internal/redact/
// policy.go RuleSet.Classify with SchemaUnknown — including unknown labels
// for compound keys that merely contain a sensitive word, where the
// token-window matcher (which is CloudFormation-only) does not apply.
// Values stay redacted either way.
func TestECSSensitiveSourceLocalLabels(t *testing.T) {
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
