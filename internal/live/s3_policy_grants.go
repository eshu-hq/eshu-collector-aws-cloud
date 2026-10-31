// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

// deriveS3PolicyFacts parses one bucket policy document transiently and
// returns only derived metadata: bounded external-principal grants and
// normalized resource-policy statements. It mirrors the in-tree awssdk
// derivation (policy.go + resource_policy.go) field for field so a shared
// document yields identical observations on both sides. The raw document,
// statement bodies, and condition values never leave this function; SameAccount
// AWS principals are skipped for grants, Deny statements emit no grant, and
// unsupported principal types retain only their type key.
func deriveS3PolicyFacts(document, bucketARN, bucketName, ownerAccountID string) ([]collector.S3ExternalPrincipalGrantObservation, []collector.ResourcePolicyPermissionObservation, error) {
	doc, err := decodeS3PolicyDocument(document)
	if err != nil {
		return nil, nil, err
	}
	owner := strings.TrimSpace(ownerAccountID)
	bucketARN = strings.TrimSpace(bucketARN)
	bucketName = strings.TrimSpace(bucketName)
	var grants []collector.S3ExternalPrincipalGrantObservation
	seen := make(map[string]struct{})
	for _, statement := range doc.statements() {
		if !statement.isAllow() {
			continue
		}
		for _, entry := range statement.principalEntries() {
			for _, grant := range grantsForS3PrincipalEntry(entry, owner, strings.TrimSpace(statement.SID)) {
				key := grant.PrincipalKind + "\x00" + grant.PrincipalValue + "\x00" + grant.GrantOutcome
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				grant.BucketARN = bucketARN
				grant.BucketName = bucketName
				grants = append(grants, grant)
			}
		}
	}
	var statements []collector.ResourcePolicyPermissionObservation
	for _, statement := range doc.statements() {
		effect := s3StatementEffect(statement.Effect)
		if effect == "" {
			continue
		}
		accountIDs, principalARNs, principalTypes, public, crossAccount := s3PrincipalFacts(statement, owner)
		statements = append(statements, collector.ResourcePolicyPermissionObservation{
			ResourceARN:         bucketARN,
			ResourceType:        catalog.ResourceTypeS3Bucket,
			StatementSID:        strings.TrimSpace(statement.SID),
			Effect:              effect,
			Actions:             s3StringList(statement.Action),
			NotActions:          s3StringList(statement.NotAction),
			Resources:           s3StringList(statement.Resource),
			NotResources:        s3StringList(statement.NotResource),
			ConditionKeys:       s3ConditionKeys(statement.Condition),
			ConditionOperators:  s3ConditionOperators(statement.Condition),
			PrincipalAccountIDs: accountIDs,
			PrincipalARNs:       principalARNs,
			PrincipalTypes:      principalTypes,
			IsPublic:            public,
			IsCrossAccount:      crossAccount,
		})
	}
	return grants, statements, nil
}

func decodeS3PolicyDocument(document string) (s3PolicyDocument, error) {
	raw := strings.TrimSpace(document)
	if raw == "" {
		return s3PolicyDocument{}, fmt.Errorf("empty bucket policy document")
	}
	// AWS sometimes URL-encodes inline policy documents; decode best-effort,
	// then parse. Mirrors the in-tree adapter handling.
	if decoded, decodeErr := url.QueryUnescape(raw); decodeErr == nil && strings.Contains(decoded, "{") {
		raw = decoded
	}
	var doc s3PolicyDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return s3PolicyDocument{}, fmt.Errorf("parse bucket policy document: %w", err)
	}
	return doc, nil
}

// s3PolicyDocument captures only Effect/Principal/Action/Resource/Condition
// shapes needed for metadata derivation. Values beyond key names are dropped
// by the accessors; nothing sensitive is retained.
type s3PolicyDocument struct {
	Statement json.RawMessage `json:"Statement"`
}

func (d s3PolicyDocument) statements() []s3PolicyStatement {
	trimmed := strings.TrimSpace(string(d.Statement))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var statements []s3PolicyStatement
		if err := json.Unmarshal(d.Statement, &statements); err != nil {
			return nil
		}
		return statements
	}
	var single s3PolicyStatement
	if err := json.Unmarshal(d.Statement, &single); err != nil {
		return nil
	}
	return []s3PolicyStatement{single}
}

type s3PolicyStatement struct {
	SID         string          `json:"Sid"`
	Effect      string          `json:"Effect"`
	Principal   json.RawMessage `json:"Principal"`
	Action      json.RawMessage `json:"Action"`
	NotAction   json.RawMessage `json:"NotAction"`
	Resource    json.RawMessage `json:"Resource"`
	NotResource json.RawMessage `json:"NotResource"`
	Condition   json.RawMessage `json:"Condition"`
}

func (s s3PolicyStatement) isAllow() bool {
	return strings.EqualFold(strings.TrimSpace(s.Effect), "Allow")
}

type s3PrincipalEntry struct {
	key    string
	values []string
}

func (s s3PolicyStatement) principalEntries() []s3PrincipalEntry {
	trimmed := strings.TrimSpace(string(s.Principal))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var asString string
	if err := json.Unmarshal(s.Principal, &asString); err == nil {
		return []s3PrincipalEntry{{key: "AWS", values: []string{asString}}}
	}
	if values := s3StringList(s.Principal); len(values) > 0 {
		return []s3PrincipalEntry{{key: "AWS", values: values}}
	}
	var asObject map[string]json.RawMessage
	if err := json.Unmarshal(s.Principal, &asObject); err != nil {
		return nil
	}
	var entries []s3PrincipalEntry
	for _, key := range orderedS3PrincipalKeys(asObject) {
		entries = append(entries, s3PrincipalEntry{
			key:    strings.TrimSpace(key),
			values: s3StringList(asObject[key]),
		})
	}
	return entries
}

func s3StringList(raw json.RawMessage) []string {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	return nil
}

func orderedS3PrincipalKeys(values map[string]json.RawMessage) []string {
	known := []string{"AWS", "Service", "Federated", "CanonicalUser"}
	var ordered []string
	seen := make(map[string]struct{}, len(values))
	for _, key := range known {
		if _, ok := values[key]; ok {
			ordered = append(ordered, key)
			seen[key] = struct{}{}
		}
	}
	var rest []string
	for key := range values {
		if _, ok := seen[key]; ok {
			continue
		}
		rest = append(rest, key)
	}
	sort.Strings(rest)
	return append(ordered, rest...)
}

func grantsForS3PrincipalEntry(entry s3PrincipalEntry, owner, statementSID string) []collector.S3ExternalPrincipalGrantObservation {
	switch entry.key {
	case "AWS":
		var grants []collector.S3ExternalPrincipalGrantObservation
		for _, value := range entry.values {
			if grant, ok := grantForS3AWSPrincipal(value, owner, statementSID); ok {
				grants = append(grants, grant)
			}
		}
		return grants
	case "Service":
		var grants []collector.S3ExternalPrincipalGrantObservation
		for _, value := range entry.values {
			service := strings.TrimSpace(value)
			if service == "" {
				continue
			}
			grants = append(grants, collector.S3ExternalPrincipalGrantObservation{
				PrincipalKind: collector.S3ExternalPrincipalKindAWSService, PrincipalValue: service,
				PrincipalService: service, GrantOutcome: collector.S3ExternalPrincipalGrantOutcomeAWSService,
				ServicePrincipal: true, SourceStatementID: statementSID,
			})
		}
		return grants
	default:
		key := strings.TrimSpace(entry.key)
		if key == "" {
			return nil
		}
		return []collector.S3ExternalPrincipalGrantObservation{{
			PrincipalKind: collector.S3ExternalPrincipalKindUnsupported, PrincipalValue: key,
			GrantOutcome: collector.S3ExternalPrincipalGrantOutcomeUnsupported,
			Unsupported:  true, UnsupportedKey: key, SourceStatementID: statementSID,
		}}
	}
}

func grantForS3AWSPrincipal(identifier, owner, statementSID string) (collector.S3ExternalPrincipalGrantObservation, bool) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return collector.S3ExternalPrincipalGrantObservation{}, false
	}
	if identifier == "*" {
		return collector.S3ExternalPrincipalGrantObservation{
			PrincipalKind: collector.S3ExternalPrincipalKindPublic, PrincipalValue: "*",
			GrantOutcome: collector.S3ExternalPrincipalGrantOutcomePublic,
			Public:       true, SourceStatementID: statementSID,
		}, true
	}
	accountID := s3PrincipalAccountID(identifier)
	if accountID != "" {
		if owner == "" || accountID == owner {
			return collector.S3ExternalPrincipalGrantObservation{}, false
		}
		kind := collector.S3ExternalPrincipalKindAWSAccount
		partition := ""
		if strings.HasPrefix(identifier, "arn:") {
			kind = collector.S3ExternalPrincipalKindAWSARN
			partition = s3PrincipalPartition(identifier)
		}
		return collector.S3ExternalPrincipalGrantObservation{
			PrincipalKind: kind, PrincipalValue: identifier,
			PrincipalAccountID: accountID, PrincipalPartition: partition,
			GrantOutcome: collector.S3ExternalPrincipalGrantOutcomeCrossAccount,
			CrossAccount: true, SourceStatementID: statementSID,
		}, true
	}
	return collector.S3ExternalPrincipalGrantObservation{
		PrincipalKind: collector.S3ExternalPrincipalKindUnsupported, PrincipalValue: "AWS",
		GrantOutcome: collector.S3ExternalPrincipalGrantOutcomeUnsupported,
		Unsupported:  true, UnsupportedKey: "AWS", SourceStatementID: statementSID,
	}, true
}

func s3PrincipalAccountID(identifier string) string {
	id := strings.TrimSpace(identifier)
	if id == "" || id == "*" {
		return ""
	}
	if isS3AccountID(id) {
		return id
	}
	if strings.HasPrefix(id, "arn:") {
		parts := strings.SplitN(id, ":", 6)
		if len(parts) >= 5 {
			if account := strings.TrimSpace(parts[4]); isS3AccountID(account) {
				return account
			}
		}
	}
	return ""
}

func s3PrincipalPartition(identifier string) string {
	id := strings.TrimSpace(identifier)
	if !strings.HasPrefix(id, "arn:") {
		return ""
	}
	parts := strings.SplitN(id, ":", 3)
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func isS3AccountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func s3StatementEffect(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "allow":
		return "Allow"
	case "deny":
		return "Deny"
	default:
		return ""
	}
}

func s3PrincipalTypeForKey(key string) string {
	switch strings.TrimSpace(key) {
	case "AWS":
		return catalog.ResourcePolicyPrincipalTypeAWS
	case "Service":
		return catalog.ResourcePolicyPrincipalTypeService
	case "Federated":
		return catalog.ResourcePolicyPrincipalTypeFederated
	case "CanonicalUser":
		return catalog.ResourcePolicyPrincipalTypeCanonical
	default:
		return ""
	}
}

func s3PrincipalFacts(statement s3PolicyStatement, owner string) (accountIDs, principalARNs, principalTypes []string, public, crossAccount bool) {
	accountSet := map[string]struct{}{}
	arnSet := map[string]struct{}{}
	typeSet := map[string]struct{}{}
	for _, entry := range statement.principalEntries() {
		if principalType := s3PrincipalTypeForKey(entry.key); principalType != "" {
			typeSet[principalType] = struct{}{}
		}
		if entry.key != "AWS" {
			continue
		}
		for _, value := range entry.values {
			identifier := strings.TrimSpace(value)
			if identifier == "" {
				continue
			}
			if identifier == "*" {
				public = true
				continue
			}
			if strings.HasPrefix(identifier, "arn:") {
				arnSet[identifier] = struct{}{}
			}
			if accountID := s3PrincipalAccountID(identifier); accountID != "" {
				accountSet[accountID] = struct{}{}
				if owner != "" && accountID != owner {
					crossAccount = true
				}
			}
		}
	}
	return sortedS3Set(accountSet), sortedS3Set(arnSet), sortedS3Set(typeSet), public, crossAccount
}

func sortedS3Set(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func s3ConditionKeys(raw json.RawMessage) []string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var operators map[string]json.RawMessage
	if err := json.Unmarshal(raw, &operators); err != nil {
		return nil
	}
	keys := map[string]struct{}{}
	for _, operatorRaw := range operators {
		var keyMap map[string]json.RawMessage
		if err := json.Unmarshal(operatorRaw, &keyMap); err != nil {
			continue
		}
		for key := range keyMap {
			if trimmedKey := strings.TrimSpace(key); trimmedKey != "" {
				keys[trimmedKey] = struct{}{}
			}
		}
	}
	return sortedS3Set(keys)
}

func s3ConditionOperators(raw json.RawMessage) []string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var operators map[string]json.RawMessage
	if err := json.Unmarshal(raw, &operators); err != nil {
		return nil
	}
	set := map[string]struct{}{}
	for operator := range operators {
		if trimmedOperator := strings.TrimSpace(operator); trimmedOperator != "" {
			set[trimmedOperator] = struct{}{}
		}
	}
	return sortedS3Set(set)
}
