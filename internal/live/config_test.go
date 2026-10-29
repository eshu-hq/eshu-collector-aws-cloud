// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"
)

func hostConfig() map[string]any {
	return map[string]any{
		"target_scopes":   map[string]any{"account_id": "055929692761"},
		"allowed_regions": []any{"us-east-1"},
		"allowed_services": []any{
			"iam", "ecr", "ec2", "eks", "elbv2", "route53", "sqs",
			"sns", "eventbridge", "s3", "rds", "dynamodb",
			"cloudwatchlogs", "cloudfront", "apigateway",
			"secretsmanager", "ssm", "ecs", "lambda",
		},
		"limits": map[string]any{
			"maxRecordsPerClaim":  5000.0,
			"maxPayloadBytes":     65536.0,
			"claimTimeoutSeconds": 300.0,
		},
	}
}

// TestParseConfigAcceptsHostActivation proves the ops-qa host shape parses:
// account, region and service allowlists, limits, and the derived live
// source URI.
func TestParseConfigAcceptsHostActivation(t *testing.T) {
	t.Parallel()

	parsed, err := ParseConfig(hostConfig())
	if err != nil {
		t.Fatalf("ParseConfig(host) error = %v", err)
	}
	if parsed.AccountID != "055929692761" {
		t.Fatalf("AccountID = %q, want 055929692761", parsed.AccountID)
	}
	if len(parsed.Regions) != 1 || parsed.Regions[0] != "us-east-1" {
		t.Fatalf("Regions = %v, want [us-east-1]", parsed.Regions)
	}
	if len(parsed.Services) != len(hostConfig()["allowed_services"].([]any)) {
		t.Fatalf("len(Services) = %d, want host allowlist length", len(parsed.Services))
	}
	if parsed.SourceURI != "aws://055929692761" {
		t.Fatalf("SourceURI = %q, want aws://055929692761", parsed.SourceURI)
	}
	if parsed.Limits.MaxRecordsPerClaim != 5000 || parsed.Limits.ClaimTimeoutSeconds != 300 {
		t.Fatalf("Limits = %+v, want host limits", parsed.Limits)
	}
}

// TestParseConfigAcceptsScopeVariants proves liberal scope shapes: a bare
// account string, a one-element scope list, and nested source-block keys all
// resolve, while multi-account scopes fail closed.
func TestParseConfigAcceptsScopeVariants(t *testing.T) {
	t.Parallel()

	bare := hostConfig()
	bare["target_scopes"] = "055929692761"
	if parsed, err := ParseConfig(bare); err != nil || parsed.AccountID != "055929692761" {
		t.Fatalf("bare string scope = (%+v, %v), want account", parsed, err)
	}
	listed := hostConfig()
	listed["target_scopes"] = []any{map[string]any{"account": "055929692761"}}
	if parsed, err := ParseConfig(listed); err != nil || parsed.AccountID != "055929692761" {
		t.Fatalf("list scope = (%+v, %v), want account", parsed, err)
	}
	multi := hostConfig()
	multi["target_scopes"] = []any{"055929692761", "123456789012"}
	if _, err := ParseConfig(multi); err == nil {
		t.Fatal("multi scope error = nil, want failure")
	}
	short := hostConfig()
	short["target_scopes"] = map[string]any{"account_id": "12345"}
	if _, err := ParseConfig(short); err == nil {
		t.Fatal("short account error = nil, want failure")
	}
}

// TestParseConfigAcceptsNestedScopeAllowlists proves the real host activation
// shape parses: the allowlists live inside the single target_scopes element,
// not top-level. The ops-qa activation sends exactly this shape; without the
// singleton-scope fallback every live claim failed closed.
func TestParseConfigAcceptsNestedScopeAllowlists(t *testing.T) {
	t.Parallel()

	nested := hostConfig()
	delete(nested, "allowed_regions")
	delete(nested, "allowed_services")
	nested["target_scopes"] = []any{map[string]any{
		"account_id":       "055929692761",
		"allowed_regions":  []any{"us-east-1"},
		"allowed_services": []any{"ec2", "s3"},
	}}
	parsed, err := ParseConfig(nested)
	if err != nil {
		t.Fatalf("ParseConfig(nested scope) error = %v", err)
	}
	if parsed.AccountID != "055929692761" || len(parsed.Regions) != 1 || len(parsed.Services) != 2 {
		t.Fatalf("nested scope parsed = %+v, want account + 1 region + 2 services", parsed)
	}
}

// TestParseConfigRejectsGaps proves missing allowlists and unknown services
// fail closed instead of scanning an unbounded or mistyped scope.
func TestParseConfigRejectsGaps(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(map[string]any){
		"no regions":      func(config map[string]any) { delete(config, "allowed_regions") },
		"no services":     func(config map[string]any) { delete(config, "allowed_services") },
		"empty regions":   func(config map[string]any) { config["allowed_regions"] = []any{} },
		"bad region":      func(config map[string]any) { config["allowed_regions"] = []any{"us_east_1"} },
		"unknown service": func(config map[string]any) { config["allowed_services"] = []any{"iam", "elb"} },
	} {
		config := hostConfig()
		mutate(config)
		if _, err := ParseConfig(config); err == nil {
			t.Fatalf("%s: error = nil, want failure", name)
		}
	}
}

// TestParseConfigHonorsOverrides proves an explicit sourceURI and a partial
// limits block flow through while absent limits select defaults.
func TestParseConfigHonorsOverrides(t *testing.T) {
	t.Parallel()

	config := hostConfig()
	config["source"] = map[string]any{"sourceURI": "aws://055929692761/custom"}
	config["limits"] = map[string]any{"maxRecordsPerClaim": 7.0}
	parsed, err := ParseConfig(config)
	if err != nil {
		t.Fatalf("ParseConfig(overrides) error = %v", err)
	}
	if parsed.SourceURI != "aws://055929692761/custom" {
		t.Fatalf("SourceURI = %q, want override", parsed.SourceURI)
	}
	if parsed.Limits.MaxRecordsPerClaim != 7 {
		t.Fatalf("MaxRecordsPerClaim = %d, want 7", parsed.Limits.MaxRecordsPerClaim)
	}
	bad := hostConfig()
	bad["limits"] = map[string]any{"maxRecordsPerClaim": "many"}
	if _, err := ParseConfig(bad); err == nil {
		t.Fatal("malformed limits error = nil, want failure")
	}
}

// TestEverySupportedServiceHasALoader proves the registry covers the whole
// advertised inventory: no allowed_services name falls through to the
// no-loader error at claim time.
func TestEverySupportedServiceHasALoader(t *testing.T) {
	t.Parallel()

	for _, service := range SupportedServices {
		if _, ok := loaders[service]; !ok {
			t.Fatalf("service %q has no loader", service)
		}
	}
}

// TestRecordFallsBackToStableTriple proves resources without an ARN still
// get a stable, unique report key.
func TestRecordFallsBackToStableTriple(t *testing.T) {
	t.Parallel()

	recorded := record("", "ssm", "us-east-1", "/app/key", "parameter")
	if recorded.ID != "ssm/us-east-1//app/key" {
		t.Fatalf("ID = %q, want service/region/name triple", recorded.ID)
	}
	if recorded.Detail == "" || recorded.Name != "/app/key" {
		t.Fatalf("record = %+v, want name and metadata", recorded)
	}
}
