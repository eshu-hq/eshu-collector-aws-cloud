// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"sort"
	"strings"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/factschema"
	iamv1 "github.com/eshu-hq/eshu-sdk/factschema/iam/v1"
)

// iamPermissionWildcardAction is the IAM action wildcard that grants every
// action. A statement whose normalized action set contains it is flagged
// is_wildcard_action so downstream posture analysis can treat it as a
// high-signal grant without re-parsing the action list.
const iamPermissionWildcardAction = "*"

// NewIAMPermissionFact builds the durable aws_iam_permission fact for one
// normalized IAM policy statement attached to a principal.
//
// The fact is derived and metadata-only: it captures the principal, effect,
// normalized action/resource patterns, and a condition-key summary. It never
// carries the raw policy JSON body or condition values. Normalization mirrors
// the in-tree NewIAMPermissionEnvelope verbatim (trimmed, lowercased actions,
// de-duplicated sorted lists, Allow/Deny effect gate) so the shared fixture
// yields the same stable key on both sides.
func NewIAMPermissionFact(observation IAMPermissionObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(observation.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	principalARN := strings.TrimSpace(observation.PrincipalARN)
	if principalARN == "" {
		return sdk.Fact{}, fmt.Errorf("aws iam permission observation requires principal_arn")
	}
	effect := normalizeIAMEffect(observation.Effect)
	if effect == "" {
		return sdk.Fact{}, fmt.Errorf("aws iam permission observation requires effect")
	}
	policySource := strings.TrimSpace(observation.PolicySource)
	if policySource == "" {
		return sdk.Fact{}, fmt.Errorf("aws iam permission observation requires policy_source")
	}

	actions := normalizeIAMActionList(observation.Actions)
	notActions := normalizeIAMActionList(observation.NotActions)
	resources := normalizeIAMPatternList(observation.Resources)
	notResources := normalizeIAMPatternList(observation.NotResources)
	conditionKeys := normalizeIAMKeyList(observation.ConditionKeys)
	conditionOperators := normalizeIAMKeyList(observation.ConditionOperators)
	assumePrincipals := normalizeIAMPatternList(observation.AssumePrincipals)

	policyARN := strings.TrimSpace(observation.PolicyARN)
	policyName := strings.TrimSpace(observation.PolicyName)
	statementSID := strings.TrimSpace(observation.StatementSID)

	stableIdentity := map[string]any{
		"account_id":    observation.Boundary.AccountID,
		"actions":       strings.Join(actions, ","),
		"effect":        effect,
		"not_actions":   strings.Join(notActions, ","),
		"not_resources": strings.Join(notResources, ","),
		"policy_arn":    policyARN,
		"policy_name":   policyName,
		"policy_source": policySource,
		"principal_arn": principalARN,
		"region":        observation.Boundary.Region,
		"resources":     strings.Join(resources, ","),
		"statement_sid": statementSID,
	}
	addConditionSummaryIdentity(stableIdentity, conditionKeys, conditionOperators)
	stableKey, err := specialtyStableKey(AWSKindIAMPermission, stableIdentity)
	if err != nil {
		return sdk.Fact{}, err
	}

	payload, err := factschema.EncodeAWSIAMPermission(iamv1.Permission{
		AccountID:              observation.Boundary.AccountID,
		Region:                 observation.Boundary.Region,
		ServiceKind:            specialtyBoundaryValue(observation.Boundary.ServiceKind),
		CollectorInstanceID:    specialtyBoundaryValue(observation.Boundary.CollectorInstanceID),
		PrincipalARN:           principalARN,
		PrincipalType:          specialtyStringPtr(strings.TrimSpace(observation.PrincipalType)),
		PolicySource:           policySource,
		PolicyARN:              specialtyStringPtr(policyARN),
		PolicyName:             specialtyStringPtr(policyName),
		StatementSID:           specialtyStringPtr(statementSID),
		Effect:                 effect,
		Actions:                actions,
		NotActions:             notActions,
		Resources:              resources,
		NotResources:           notResources,
		ConditionKeys:          conditionKeys,
		ConditionOperators:     conditionOperators,
		ConditionOperatorCount: specialtyIntPtr(len(conditionOperators)),
		AssumePrincipals:       assumePrincipals,
		HasConditions:          specialtyBoolPtr(len(conditionKeys) > 0 || len(conditionOperators) > 0),
		IsWildcardAction:       specialtyBoolPtr(iamContainsValue(actions, iamPermissionWildcardAction)),
		IsWildcardResource:     specialtyBoolPtr(iamContainsValue(resources, iamPermissionWildcardAction)),
	})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode aws_iam_permission payload: %w", err)
	}

	recordID := strings.TrimSpace(observation.SourceRecordID)
	if recordID == "" {
		recordID = iamPermissionSourceID(principalARN, policySource, policyARN, policyName, statementSID, effect, actions)
	}
	return specialtyFact(AWSKindIAMPermission, stableKey, observation.Boundary, observation.SourceURI, recordID, payload)
}

// normalizeIAMEffect canonicalizes an IAM statement effect to "Allow" or
// "Deny", returning "" for any other value so the builder rejects malformed
// statements.
func normalizeIAMEffect(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "allow":
		return "Allow"
	case "deny":
		return "Deny"
	default:
		return ""
	}
}

// normalizeIAMActionList trims, lowercases, de-duplicates, and sorts IAM action
// strings. Actions are case-insensitive AWS API identifiers, so lowercasing
// gives a stable, comparable set across documents that vary the casing.
func normalizeIAMActionList(values []string) []string {
	return normalizeIAMStrings(values, strings.ToLower)
}

// normalizeIAMPatternList trims, de-duplicates, and sorts resource/principal
// ARN patterns. ARNs are case-sensitive, so the values are preserved verbatim
// apart from surrounding whitespace.
func normalizeIAMPatternList(values []string) []string {
	return normalizeIAMStrings(values, nil)
}

// normalizeIAMKeyList trims, de-duplicates, and sorts condition keys. Keys are
// preserved verbatim (apart from whitespace) so the summary names the exact
// condition keys without leaking their values.
func normalizeIAMKeyList(values []string) []string {
	return normalizeIAMStrings(values, nil)
}

// normalizeIAMStrings trims each value, drops empties, optionally maps the
// survivor (for case folding), de-duplicates, and returns a sorted slice. It
// returns a non-nil empty slice for empty input so payload list fields stay
// typed.
func normalizeIAMStrings(values []string, mapFn func(string) string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if mapFn != nil {
			trimmed = mapFn(trimmed)
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

// iamContainsValue reports whether values contains target. The lists are small
// (action/resource sets), so a linear scan is the simplest correct check.
func iamContainsValue(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// iamPermissionSourceID builds a deterministic source record id for a derived
// permission statement so repeated observations of the same statement map to
// one durable fact within a generation.
func iamPermissionSourceID(principalARN, policySource, policyARN, policyName, statementSID, effect string, actions []string) string {
	policyRef := policyARN
	if policyRef == "" {
		policyRef = policyName
	}
	parts := []string{principalARN, policySource, policyRef, statementSID, effect, strings.Join(actions, ",")}
	return strings.Join(parts, "#")
}
