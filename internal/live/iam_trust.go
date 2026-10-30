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

// iamTrustPrincipal identifies one principal granted access by a role trust
// policy. It mirrors the in-tree scanner-owned TrustPrincipal so emitted
// attributes and edges agree field for field.
type iamTrustPrincipal struct {
	Type       string
	Identifier string
}

// parseIAMTrustPolicy derives trust presence and principals from a role's
// reported trust document. It mirrors the in-tree trust parser verbatim: URL
// decoding with raw fallback, an error on malformed JSON that never carries
// the raw value, principals from the Principal key only, statement-order
// preservation across statements, and sorted principal-type order within one
// statement. A bare-string principal normalizes to an AWS-typed entry.
func parseIAMTrustPolicy(raw string) (bool, []iamTrustPrincipal, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false, nil, nil
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		decoded = raw
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(decoded), &document); err != nil {
		return false, nil, fmt.Errorf("invalid IAM role trust policy document")
	}
	return len(document) > 0, iamTrustPrincipals(document), nil
}

func iamTrustPrincipals(document map[string]any) []iamTrustPrincipal {
	statements, ok := document["Statement"].([]any)
	if !ok {
		if single, ok := document["Statement"].(map[string]any); ok {
			statements = []any{single}
		}
	}
	var principals []iamTrustPrincipal
	for _, statement := range statements {
		statementMap, ok := statement.(map[string]any)
		if !ok {
			continue
		}
		principals = append(principals, iamTrustPrincipalEntries(statementMap["Principal"])...)
	}
	return principals
}

func iamTrustPrincipalEntries(value any) []iamTrustPrincipal {
	switch typed := value.(type) {
	case string:
		identifier := strings.TrimSpace(typed)
		if identifier == "" {
			return nil
		}
		return []iamTrustPrincipal{{Type: "AWS", Identifier: identifier}}
	case []any:
		var principals []iamTrustPrincipal
		for _, item := range typed {
			principals = append(principals, iamTrustPrincipalEntries(item)...)
		}
		return principals
	case map[string]any:
		// Range over sorted principal-type keys: Go map iteration is
		// random, and the trust_principals attribute plus trust-edge
		// emission order must be deterministic. Statement order is still
		// preserved by the caller; single-key statements are unaffected.
		keys := make([]string, 0, len(typed))
		for principalType := range typed {
			keys = append(keys, principalType)
		}
		sort.Strings(keys)
		var principals []iamTrustPrincipal
		for _, principalType := range keys {
			for _, identifier := range iamPrincipalIdentifiers(typed[principalType]) {
				principals = append(principals, iamTrustPrincipal{
					Type:       principalType,
					Identifier: identifier,
				})
			}
		}
		return principals
	default:
		return nil
	}
}

func iamPrincipalIdentifiers(value any) []string {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{strings.TrimSpace(typed)}
	case []any:
		output := make([]string, 0, len(typed))
		for _, item := range typed {
			if value, ok := item.(string); ok && strings.TrimSpace(value) != "" {
				output = append(output, strings.TrimSpace(value))
			}
		}
		return output
	default:
		return nil
	}
}

// iamTrustPrincipalAttrMaps projects principals into the attribute shape the
// in-tree role resource carries: one type/identifier map per principal, nil
// when there are none.
func iamTrustPrincipalAttrMaps(principals []iamTrustPrincipal) []map[string]string {
	if len(principals) == 0 {
		return nil
	}
	output := make([]map[string]string, 0, len(principals))
	for _, principal := range principals {
		output = append(output, map[string]string{
			"type":       strings.TrimSpace(principal.Type),
			"identifier": strings.TrimSpace(principal.Identifier),
		})
	}
	return output
}

// iamTrustRelationships maps trust principals into role->principal edges,
// mirroring the in-tree trust relationship shape including the empty target
// ARN and the Type:Identifier target identity.
func iamTrustRelationships(roleARN string, principals []iamTrustPrincipal) []collector.LiveRelationship {
	roleARN = strings.TrimSpace(roleARN)
	edges := make([]collector.LiveRelationship, 0, len(principals))
	for _, principal := range principals {
		principalType := strings.TrimSpace(principal.Type)
		identifier := strings.TrimSpace(principal.Identifier)
		principalID := principalType + ":" + identifier
		edges = append(edges, collector.LiveRelationship{
			Region:           "aws-global",
			ServiceKind:      catalog.ServiceIAM,
			RelationshipType: catalog.RelationshipIAMRoleTrustsPrincipal,
			SourceResourceID: roleARN,
			SourceARN:        roleARN,
			TargetResourceID: principalID,
			TargetType:       catalog.ResourceTypeIAMPrincipal,
			SourceRecordID:   roleARN + "#trust#" + principalID,
			Attributes: map[string]any{
				"principal_type": principalType,
			},
		})
	}
	return edges
}

// iamAttachedPolicyRelationships maps a role's attached managed policy ARNs
// into role->policy edges, mirroring the in-tree attached-policy
// relationship shape.
func iamAttachedPolicyRelationships(roleARN string, policyARNs []string) []collector.LiveRelationship {
	roleARN = strings.TrimSpace(roleARN)
	edges := make([]collector.LiveRelationship, 0, len(policyARNs))
	for _, policyARN := range policyARNs {
		policyARN = strings.TrimSpace(policyARN)
		if policyARN == "" {
			continue
		}
		edges = append(edges, collector.LiveRelationship{
			Region:           "aws-global",
			ServiceKind:      catalog.ServiceIAM,
			RelationshipType: catalog.RelationshipIAMRoleAttachedPolicy,
			SourceResourceID: roleARN,
			SourceARN:        roleARN,
			TargetResourceID: policyARN,
			TargetARN:        policyARN,
			TargetType:       catalog.ResourceTypeIAMPolicy,
			SourceRecordID:   roleARN + "#policy#" + policyARN,
		})
	}
	return edges
}
