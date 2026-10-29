// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"
)

func hostConfig() map[string]any {
	return map[string]any{
		"target_scopes":   map[string]any{"account_id": "111122223333"},
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
	if parsed.AccountID != "111122223333" {
		t.Fatalf("AccountID = %q, want 111122223333", parsed.AccountID)
	}
	if len(parsed.Regions) != 1 || parsed.Regions[0] != "us-east-1" {
		t.Fatalf("Regions = %v, want [us-east-1]", parsed.Regions)
	}
	allowed, ok := hostConfig()["allowed_services"].([]any)
	if !ok {
		t.Fatalf("host allowed_services has unexpected type %T", hostConfig()["allowed_services"])
	}
	if len(parsed.Services) != len(allowed) {
		t.Fatalf("len(Services) = %d, want host allowlist length", len(parsed.Services))
	}
	if parsed.SourceURI != "aws://111122223333" {
		t.Fatalf("SourceURI = %q, want aws://111122223333", parsed.SourceURI)
	}
	if parsed.Limits.MaxRecordsPerClaim != 5000 || parsed.Limits.ClaimTimeoutSeconds != 300 {
		t.Fatalf("Limits = %+v, want host limits", parsed.Limits)
	}
}

// TestParseConfigReadsScopeCredentials proves the opt-in cross-account
// shape: a scope carrying credentials resolves its role ARN and external ID,
// while malformed credential blocks fail closed.
func TestParseConfigReadsScopeCredentials(t *testing.T) {
	t.Parallel()

	withCreds := hostConfig()
	withCreds["target_scopes"] = []any{map[string]any{
		"account_id": "111122223333",
		"assume_role": map[string]any{
			"mode":        "central_assume_role",
			"role_arn":    "arn:aws:iam::111122223333:role/irsa-eshu-aws-collector-cross-account-role",
			"external_id": "eshu-ops-qa-collector",
		},
	}}
	parsed, err := ParseConfig(withCreds)
	if err != nil {
		t.Fatalf("ParseConfig(credentials) error = %v", err)
	}
	if parsed.AccountID != "111122223333" {
		t.Fatalf("AccountID = %q, want 111122223333", parsed.AccountID)
	}
	if parsed.RoleARN != "arn:aws:iam::111122223333:role/irsa-eshu-aws-collector-cross-account-role" {
		t.Fatalf("RoleARN = %q, want the scope role", parsed.RoleARN)
	}
	if parsed.ExternalID != "eshu-ops-qa-collector" {
		t.Fatalf("ExternalID = %q, want eshu-ops-qa-collector", parsed.ExternalID)
	}

	plain, err := ParseConfig(hostConfig())
	if err != nil {
		t.Fatalf("ParseConfig(host) error = %v", err)
	}
	if plain.RoleARN != "" || plain.ExternalID != "" {
		t.Fatalf("RoleARN/ExternalID = %q/%q, want empty without an assume_role block",
			plain.RoleARN, plain.ExternalID)
	}

	rejects := map[string]map[string]any{
		"unknown mode": {
			"mode": "static_keys", "role_arn": "arn:aws:iam::111122223333:role/r", "external_id": "e",
		},
		"missing mode": {
			"role_arn": "arn:aws:iam::111122223333:role/r", "external_id": "e",
		},
		"malformed ARN": {
			"mode": "central_assume_role", "role_arn": "not-an-arn", "external_id": "e",
		},
		"role in another account": {
			"mode":        "central_assume_role",
			"role_arn":    "arn:aws:iam::444455556666:role/foreign-collector",
			"external_id": "e",
		},
		"empty external id": {
			"mode": "central_assume_role", "role_arn": "arn:aws:iam::111122223333:role/r", "external_id": "  ",
		},
	}
	for name, creds := range rejects {
		cfg := hostConfig()
		cfg["target_scopes"] = []any{map[string]any{"account_id": "111122223333", "assume_role": creds}}
		if _, err := ParseConfig(cfg); err == nil {
			t.Errorf("ParseConfig(%s) error = nil, want fail-closed", name)
		}
	}
}

// TestParseConfigReadsMapShapeCredentials proves a map-shape target_scopes
// (first-class host input per parseAccount) carries credentials like the
// singleton list does, and a multi-scope list with credentials fails closed
// instead of silently reading ambient.
func TestParseConfigReadsMapShapeCredentials(t *testing.T) {
	t.Parallel()

	creds := map[string]any{
		"mode":        "central_assume_role",
		"role_arn":    "arn:aws:iam::111122223333:role/irsa-eshu-aws-collector-cross-account-role",
		"external_id": "eshu-ops-qa-collector",
	}
	mapShape := hostConfig()
	mapShape["target_scopes"] = map[string]any{"account_id": "111122223333", "assume_role": creds}
	parsed, err := ParseConfig(mapShape)
	if err != nil {
		t.Fatalf("ParseConfig(map credentials) error = %v", err)
	}
	if parsed.RoleARN == "" || parsed.ExternalID != "eshu-ops-qa-collector" {
		t.Fatalf("RoleARN/ExternalID = %q/%q, want the map-shape scope role", parsed.RoleARN, parsed.ExternalID)
	}

	multi := hostConfig()
	multi["target_scopes"] = []any{
		map[string]any{"account_id": "111122223333", "assume_role": creds},
		map[string]any{"account_id": "444455556666"},
	}
	if _, err := ParseConfig(multi); err == nil {
		t.Fatal("ParseConfig(multi-scope credentials) error = nil, want fail-closed")
	}
	// The multi-scope credentials check lives in credentialScope itself so
	// it does not depend on ParseConfig's account-first ordering.
	multiScopes := map[string]any{"target_scopes": []any{
		map[string]any{"account_id": "111122223333", "assume_role": creds},
		map[string]any{"account_id": "444455556666"},
	}}
	if _, err := credentialScope(multiScopes); err == nil {
		t.Fatal("credentialScope(multi-scope credentials) error = nil, want fail-closed")
	}
}

// TestParseConfigAcceptsScopeVariants proves liberal scope shapes: a bare
// account string, a one-element scope list, and nested source-block keys all
// resolve, while multi-account scopes fail closed.
func TestParseConfigAcceptsScopeVariants(t *testing.T) {
	t.Parallel()

	bare := hostConfig()
	bare["target_scopes"] = "111122223333"
	if parsed, err := ParseConfig(bare); err != nil || parsed.AccountID != "111122223333" {
		t.Fatalf("bare string scope = (%+v, %v), want account", parsed, err)
	}
	listed := hostConfig()
	listed["target_scopes"] = []any{map[string]any{"account": "111122223333"}}
	if parsed, err := ParseConfig(listed); err != nil || parsed.AccountID != "111122223333" {
		t.Fatalf("list scope = (%+v, %v), want account", parsed, err)
	}
	multi := hostConfig()
	multi["target_scopes"] = []any{"111122223333", "123456789012"}
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
		"account_id":       "111122223333",
		"allowed_regions":  []any{"us-east-1"},
		"allowed_services": []any{"ec2", "s3"},
	}}
	parsed, err := ParseConfig(nested)
	if err != nil {
		t.Fatalf("ParseConfig(nested scope) error = %v", err)
	}
	if parsed.AccountID != "111122223333" || len(parsed.Regions) != 1 || len(parsed.Services) != 2 {
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
	config["source"] = map[string]any{"sourceURI": "aws://111122223333/custom"}
	config["limits"] = map[string]any{"maxRecordsPerClaim": 7.0}
	parsed, err := ParseConfig(config)
	if err != nil {
		t.Fatalf("ParseConfig(overrides) error = %v", err)
	}
	if parsed.SourceURI != "aws://111122223333/custom" {
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
