// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// SupportedServices is the live-read inventory this package implements: the
// configured AWS service names. The ops-qa host currently allows a subset.
var SupportedServices = []string{
	"apigateway",
	"cloudfront",
	"cloudwatchlogs",
	"dynamodb",
	"ec2",
	"ecr",
	"ecs",
	"eks",
	"elbv2",
	"eventbridge",
	"iam",
	"lambda",
	"kms",
	"rds",
	"route53",
	"s3",
	"secretsmanager",
	"sns",
	"sqs",
	"ssm",
}

var (
	accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern  = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z-]+-[0-9]+$`)
)

// Config is the parsed live-source activation: everything parseSDKStdio
// learns from a host request that carries no source.input file.
type Config struct {
	AccountID string
	Regions   []string
	Services  []string
	// RoleARN and ExternalID carry the opt-in cross-account credentials for
	// the scope: when set, collection assumes the role (STS AssumeRole with
	// the external ID) instead of reading with ambient credentials. Both
	// empty means ambient credentials, the historical single-account shape.
	// A role in any account but the scope account is rejected at parse.
	RoleARN    string
	ExternalID string
	SourceURI  string
	// PreviousDigest is the host hint; live collection currently ignores it
	// until typed resources and failed service pairs enter the digest.
	PreviousDigest string
	Limits         collector.ResourceUse
}

// Supported reports whether name is a live-read service.
func Supported(name string) bool {
	for _, service := range SupportedServices {
		if name == service {
			return true
		}
	}
	return false
}

// ParseConfig decodes the host activation config. The live keys are read
// top-level first (target_scopes, allowed_regions, allowed_services) with a
// fallback to the source block, because hosts nest activation differently;
// source.sourceURI, freshness.previousDigest, and limits reuse the file-mode
// shapes. A missing account, region, or service allowlist fails closed: live
// collection never runs against an unbounded scope.
func ParseConfig(config map[string]any) (Config, error) {
	parsed := Config{Limits: collector.DefaultResourceUse()}
	account, err := parseAccount(config)
	if err != nil {
		return Config{}, err
	}
	regions, err := parseStringList(config, "allowed_regions", "regions")
	if err != nil {
		return Config{}, err
	}
	for _, region := range regions {
		if !regionPattern.MatchString(region) {
			return Config{}, fmt.Errorf("config allowed_regions entry %q is not an AWS region", region)
		}
	}
	services, err := parseStringList(config, "allowed_services", "services")
	if err != nil {
		return Config{}, err
	}
	for _, service := range services {
		if !Supported(service) {
			return Config{}, fmt.Errorf("config allowed_services entry %q is not a live-read service (supported: %s)",
				service, strings.Join(SupportedServices, ", "))
		}
	}
	sourceURI, present, err := optionalString(config, "source", "sourceURI")
	if err != nil {
		return Config{}, err
	}
	if !present || strings.TrimSpace(sourceURI) == "" {
		sourceURI = "aws://" + account
	}
	previousDigest, _, err := optionalString(config, "freshness", "previousDigest")
	if err != nil {
		return Config{}, err
	}
	limits, err := parseLimits(config)
	if err != nil {
		return Config{}, err
	}
	roleARN, externalID, err := parseCredentials(config, account)
	if err != nil {
		return Config{}, err
	}
	parsed.AccountID = account
	parsed.RoleARN = roleARN
	parsed.ExternalID = externalID
	parsed.Regions = regions
	parsed.Services = services
	parsed.SourceURI = sourceURI
	parsed.PreviousDigest = previousDigest
	parsed.Limits = limits
	return parsed, nil
}

// parseAccount resolves the target AWS account from target_scopes, which the
// host sends as a map (account_id), a bare string, or a one-element list.
// Anything else fails closed.
func parseAccount(config map[string]any) (string, error) {
	raw := firstPresent(config, "target_scopes")
	if raw == nil {
		if nested, ok := config["source"].(map[string]any); ok {
			raw = firstPresent(nested, "target_scopes")
		}
	}
	account, err := accountFrom(raw)
	if err != nil {
		return "", err
	}
	if account == "" {
		return "", fmt.Errorf("config target_scopes.account_id missing")
	}
	if !accountPattern.MatchString(account) {
		return "", fmt.Errorf("config target_scopes.account_id is not a 12-digit account")
	}
	return account, nil
}

func accountFrom(raw any) (string, error) {
	switch value := raw.(type) {
	case nil:
		return "", nil
	case string:
		return strings.TrimSpace(value), nil
	case map[string]any:
		for _, key := range []string{"account_id", "accountId", "account", "id", "accountID"} {
			if candidate, ok := value[key].(string); ok {
				return strings.TrimSpace(candidate), nil
			}
		}
		if len(value) == 0 {
			return "", nil
		}
		return "", fmt.Errorf("config target_scopes map carries no account_id")
	case []any:
		if len(value) == 0 {
			return "", nil
		}
		if len(value) > 1 {
			return "", fmt.Errorf("config target_scopes lists %d scopes, this collector serves one account per claim", len(value))
		}
		return accountFrom(value[0])
	default:
		return "", fmt.Errorf("config target_scopes must be an object, string, or single-element list")
	}
}

// parseStringList reads a non-empty string list from the first present key,
// falling back to the source block. Entries are trimmed and lowercased so
// "Lambda" and " lambda " still resolve; empties fail closed.
func parseStringList(config map[string]any, keys ...string) ([]string, error) {
	raw := firstPresent(config, keys...)
	if raw == nil {
		if nested, ok := config["source"].(map[string]any); ok {
			raw = firstPresent(nested, keys...)
		}
	}
	// The host nests per-scope allowlists inside the single target_scopes
	// element (account_id plus allowed_regions/allowed_services); nothing
	// sends them top-level, so resolve the singleton scope the same way
	// parseAccount does before failing closed.
	if raw == nil {
		if scope := scopeSingleton(config); scope != nil {
			raw = firstPresent(scope, keys...)
		}
	}
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("config %q missing (non-empty list required)", keys[0])
	}
	parsed := make([]string, 0, len(list))
	for _, entry := range list {
		text, ok := entry.(string)
		if !ok || strings.TrimSpace(text) == "" {
			return nil, fmt.Errorf("config %q entries must be non-empty strings", keys[0])
		}
		parsed = append(parsed, strings.ToLower(strings.TrimSpace(text)))
	}
	sort.Strings(parsed)
	return parsed, nil
}

// scopeSingleton returns the single target scope object when target_scopes
// is a one-element list of objects (the host activation shape), or nil
// otherwise. Multi-scope lists fail closed in accountFrom; here they resolve
// to nothing so the caller reports the list itself missing.
func scopeSingleton(config map[string]any) map[string]any {
	raw := firstPresent(config, "target_scopes")
	if raw == nil {
		if nested, ok := config["source"].(map[string]any); ok {
			raw = firstPresent(nested, "target_scopes")
		}
	}
	list, ok := raw.([]any)
	if !ok || len(list) != 1 {
		return nil
	}
	scope, ok := list[0].(map[string]any)
	if !ok {
		return nil
	}
	return scope
}

// credentialScope resolves the scope object that may carry a credentials
// block: the singleton-list element or a map-shape target_scopes (both are
// first-class host input per parseAccount). A bare account string has no
// scope object. A multi-scope list with credentials anywhere fails closed:
// the role cannot be attributed to one account.
func credentialScope(config map[string]any) (map[string]any, error) {
	raw := firstPresent(config, "target_scopes")
	if raw == nil {
		if nested, ok := config["source"].(map[string]any); ok {
			raw = firstPresent(nested, "target_scopes")
		}
	}
	switch value := raw.(type) {
	case nil:
		return nil, nil
	case map[string]any:
		return value, nil
	case []any:
		if len(value) == 1 {
			scope, ok := value[0].(map[string]any)
			if !ok {
				return nil, nil
			}
			return scope, nil
		}
		// A multi-scope list carrying credentials anywhere fails closed
		// here too, so the check does not depend on ParseConfig calling
		// parseAccount first. (Via ParseConfig the account check fires
		// first; this guards direct callers and reorderings.)
		for _, entry := range value {
			if scope, ok := entry.(map[string]any); ok {
				if _, has := scope["assume_role"]; has {
					return nil, fmt.Errorf("config target_scopes lists %d scopes with assume_role: one account per claim", len(value))
				}
			}
		}
		return nil, nil
	default:
		return nil, nil
	}
}

// roleARNPattern admits only IAM role ARNs: no user, policy, or
// instance-profile ARN can smuggle through the credentials block.
var roleARNPattern = regexp.MustCompile(`^arn:(aws|aws-us-gov):iam::([0-9]{12}):role/(.+)$`)

// parseCredentials resolves the opt-in cross-account block from the singleton
// scope object (the same level as account_id, mirroring the coordinator's
// per-scope credentials shape). Absent means ambient credentials. Anything
// malformed fails closed, including a role in any account but the scope
// account: the guard pins the assume target to the scope so a copied block
// can never read a foreign account.
func parseCredentials(config map[string]any, account string) (string, string, error) {
	scope, err := credentialScope(config)
	if err != nil {
		return "", "", err
	}
	if scope == nil {
		return "", "", nil
	}
	if _, stale := scope["credentials"]; stale {
		return "", "", fmt.Errorf("config target_scopes credentials was renamed to assume_role")
	}
	raw, ok := scope["assume_role"]
	if !ok || raw == nil {
		return "", "", nil
	}
	creds, ok := raw.(map[string]any)
	if !ok {
		return "", "", fmt.Errorf("config target_scopes assume_role must be an object")
	}
	mode, ok := creds["mode"].(string)
	if !ok || mode != "central_assume_role" {
		return "", "", fmt.Errorf("config target_scopes assume_role mode %#v is not supported (want central_assume_role)", creds["mode"])
	}
	roleARN, ok := creds["role_arn"].(string)
	if !ok {
		return "", "", fmt.Errorf("config target_scopes assume_role role_arn must be a string")
	}
	roleARN = strings.TrimSpace(roleARN)
	match := roleARNPattern.FindStringSubmatch(roleARN)
	if match == nil || strings.TrimSpace(match[3]) == "" {
		return "", "", fmt.Errorf("config target_scopes assume_role role_arn %q is not an IAM role ARN", roleARN)
	}
	if match[2] != account {
		return "", "", fmt.Errorf("config target_scopes assume_role role_arn account %q does not match scope account %q", match[2], account)
	}
	externalID, ok := creds["external_id"].(string)
	if !ok || strings.TrimSpace(externalID) == "" {
		return "", "", fmt.Errorf("config target_scopes assume_role external_id is required")
	}
	return roleARN, strings.TrimSpace(externalID), nil
}

func firstPresent(config map[string]any, keys ...string) any {
	for _, key := range keys {
		if raw, ok := config[key]; ok && raw != nil {
			return raw
		}
	}
	return nil
}

// optionalString separates "missing" (present=false, caller may default)
// from "malformed" (err non-nil, caller must fail closed).
func optionalString(config map[string]any, keys ...string) (string, bool, error) {
	var current any = config
	for _, key := range keys {
		node, ok := current.(map[string]any)
		if !ok {
			if current != nil {
				return "", true, fmt.Errorf("config %q must be an object", strings.Join(keys, "."))
			}
			return "", false, nil
		}
		current, ok = node[key]
		if !ok {
			return "", false, nil
		}
	}
	text, ok := current.(string)
	if !ok {
		return "", true, fmt.Errorf("config %q must be a string", strings.Join(keys, "."))
	}
	return text, true, nil
}

// parseLimits reads limits.maxRecordsPerClaim, limits.maxPayloadBytes, and
// limits.claimTimeoutSeconds; absent fields select DefaultResourceUse and
// malformed values fail closed.
func parseLimits(config map[string]any) (collector.ResourceUse, error) {
	limits := collector.DefaultResourceUse()
	for _, field := range []struct {
		key    string
		target *int
	}{
		{"maxRecordsPerClaim", &limits.MaxRecordsPerClaim},
		{"maxPayloadBytes", &limits.MaxPayloadBytes},
		{"claimTimeoutSeconds", &limits.ClaimTimeoutSeconds},
	} {
		raw, present, err := optionalNumber(config, "limits", field.key)
		if err != nil {
			return collector.ResourceUse{}, err
		}
		if present {
			*field.target = raw
		}
	}
	return limits, nil
}

func optionalNumber(config map[string]any, keys ...string) (int, bool, error) {
	var current any = config
	for _, key := range keys {
		node, ok := current.(map[string]any)
		if !ok {
			if current != nil {
				return 0, true, fmt.Errorf("config %q must be an object", strings.Join(keys, "."))
			}
			return 0, false, nil
		}
		current, ok = node[key]
		if !ok {
			return 0, false, nil
		}
	}
	number, ok := current.(float64)
	if !ok || number != float64(int(number)) || number <= 0 {
		return 0, true, fmt.Errorf("config %q must be a positive integer", strings.Join(keys, "."))
	}
	return int(number), true, nil
}
