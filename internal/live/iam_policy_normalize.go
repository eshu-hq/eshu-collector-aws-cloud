// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	iamservice "github.com/eshu-hq/eshu-collector-aws-cloud/internal/service/iam"
)

// This file ports the in-tree awssdk policy_normalize.go statement
// projection verbatim: identifiers and patterns only (effect, SID,
// action/resource strings, condition key/operator names). The raw JSON body
// is parsed and discarded; condition values are never retained. One
// deliberate omission: the in-tree web-identity subject fingerprints have no
// carrier on IAMPermissionObservation and no posture seam in this module, so
// trust statements keep only the assume principals. The emitted trust
// principal identities already cover that evidence via trust_principals.

// normalizeIAMPolicyDocument parses one IAM identity policy document (inline
// or attached managed) into normalized, metadata-only PolicyStatement values.
func normalizeIAMPolicyDocument(raw, source, policyARN, policyName string) ([]iamservice.PolicyStatement, error) {
	document, err := decodeIAMPolicyDocument(raw)
	if err != nil {
		return nil, err
	}
	if document == nil {
		return nil, nil
	}
	rawStatements := iamDocumentStatements(document)
	statements := make([]iamservice.PolicyStatement, 0, len(rawStatements))
	for _, rawStatement := range rawStatements {
		statement, ok := normalizeIAMIdentityStatement(rawStatement, source, policyARN, policyName)
		if ok {
			statements = append(statements, statement)
		}
	}
	if len(statements) == 0 {
		return nil, nil
	}
	return statements, nil
}

// normalizeIAMTrustPolicyDocument parses a role trust / assume-role policy
// document into normalized trust statements. Each statement records the
// assume-role actions and principals without condition values.
func normalizeIAMTrustPolicyDocument(raw string) ([]iamservice.PolicyStatement, error) {
	document, err := decodeIAMPolicyDocument(raw)
	if err != nil {
		return nil, err
	}
	if document == nil {
		return nil, nil
	}
	rawStatements := iamDocumentStatements(document)
	statements := make([]iamservice.PolicyStatement, 0, len(rawStatements))
	for _, rawStatement := range rawStatements {
		statement, ok := normalizeIAMTrustStatement(rawStatement)
		if ok {
			statements = append(statements, statement)
		}
	}
	if len(statements) == 0 {
		return nil, nil
	}
	return statements, nil
}

// decodeIAMPolicyDocument URL-decodes and JSON-parses a policy document. It
// returns (nil, nil) for a blank document so callers treat "no policy" as a
// non-error. The error never carries the raw document.
func decodeIAMPolicyDocument(raw string) (map[string]any, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		decoded = raw
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(decoded), &document); err != nil {
		return nil, fmt.Errorf("parse IAM policy document: %w", err)
	}
	return document, nil
}

// iamDocumentStatements returns the statement list of a policy document,
// tolerating the single-object form IAM allows ("Statement": {..}).
func iamDocumentStatements(document map[string]any) []map[string]any {
	switch typed := document["Statement"].(type) {
	case []any:
		statements := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if statement, ok := item.(map[string]any); ok {
				statements = append(statements, statement)
			}
		}
		return statements
	case map[string]any:
		return []map[string]any{typed}
	default:
		return nil
	}
}

// normalizeIAMIdentityStatement maps one identity-policy statement object
// into a PolicyStatement. It returns ok=false for a statement with no effect
// so the caller skips malformed entries.
func normalizeIAMIdentityStatement(statement map[string]any, source, policyARN, policyName string) (iamservice.PolicyStatement, bool) {
	effect := normalizeIAMEffect(statement["Effect"])
	if effect == "" {
		return iamservice.PolicyStatement{}, false
	}
	return iamservice.PolicyStatement{
		Source:             source,
		PolicyARN:          policyARN,
		PolicyName:         policyName,
		StatementSID:       iamStringField(statement["Sid"]),
		Effect:             effect,
		Actions:            iamStringList(statement["Action"]),
		NotActions:         iamStringList(statement["NotAction"]),
		Resources:          iamStringList(statement["Resource"]),
		NotResources:       iamStringList(statement["NotResource"]),
		ConditionKeys:      iamConditionKeys(statement["Condition"]),
		ConditionOperators: iamConditionOperators(statement["Condition"]),
	}, true
}

// normalizeIAMTrustStatement maps one trust-policy statement object into a
// trust PolicyStatement, capturing the assume-role principals without their
// condition values.
func normalizeIAMTrustStatement(statement map[string]any) (iamservice.PolicyStatement, bool) {
	effect := normalizeIAMEffect(statement["Effect"])
	if effect == "" {
		return iamservice.PolicyStatement{}, false
	}
	return iamservice.PolicyStatement{
		Source:             iamservice.PolicySourceTrust,
		Effect:             effect,
		Actions:            iamStringList(statement["Action"]),
		ConditionKeys:      iamConditionKeys(statement["Condition"]),
		ConditionOperators: iamConditionOperators(statement["Condition"]),
		AssumePrincipals:   iamTrustStatementPrincipals(statement["Principal"]),
	}, true
}

// iamTrustStatementPrincipals flattens a statement's Principal element into
// the principal identifiers it names, reusing the trust-principal parser so
// the derived fact agrees with the emitted trust relationships.
func iamTrustStatementPrincipals(value any) []string {
	principals := iamTrustPrincipalEntries(value)
	out := make([]string, 0, len(principals))
	for _, principal := range principals {
		if identifier := strings.TrimSpace(principal.Identifier); identifier != "" {
			out = append(out, identifier)
		}
	}
	return out
}

// iamConditionKeys returns the sorted, de-duplicated condition keys present
// on a statement's Condition element. Only keys are kept; values (which can
// embed source IPs, tags, or other sensitive selectors) are dropped.
func iamConditionKeys(value any) []string {
	operators, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	seen := make(map[string]struct{})
	for _, operatorValue := range operators {
		keyMap, ok := operatorValue.(map[string]any)
		if !ok {
			continue
		}
		for key := range keyMap {
			if key = strings.TrimSpace(key); key != "" {
				seen[key] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// iamConditionOperators returns the sorted, de-duplicated top-level
// Condition operators present on a statement. Only operator names are kept;
// values are dropped.
func iamConditionOperators(value any) []string {
	operators, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	seen := make(map[string]struct{})
	for operator := range operators {
		if operator = strings.TrimSpace(operator); operator != "" {
			seen[operator] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for operator := range seen {
		out = append(out, operator)
	}
	sort.Strings(out)
	return out
}

// normalizeIAMEffect canonicalizes a statement Effect to "Allow" or "Deny",
// or "" for any other value.
func normalizeIAMEffect(value any) string {
	str, ok := value.(string)
	if !ok {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(str)) {
	case "allow":
		return "Allow"
	case "deny":
		return "Deny"
	default:
		return ""
	}
}

// iamStringField returns the trimmed string value of a JSON element, or ""
// when it is not a string.
func iamStringField(value any) string {
	if typed, ok := value.(string); ok {
		return strings.TrimSpace(typed)
	}
	return ""
}

// iamStringList coerces a JSON element that is either a string or an array of
// strings into non-empty trimmed strings. IAM Action/Resource elements use
// both forms interchangeably.
func iamStringList(value any) []string {
	switch typed := value.(type) {
	case string:
		if trimmed := strings.TrimSpace(typed); trimmed != "" {
			return []string{trimmed}
		}
		return nil
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if str, ok := item.(string); ok {
				if trimmed := strings.TrimSpace(str); trimmed != "" {
					out = append(out, trimmed)
				}
			}
		}
		return out
	default:
		return nil
	}
}
