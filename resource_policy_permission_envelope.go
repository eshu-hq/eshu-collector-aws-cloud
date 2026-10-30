// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"strings"

	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/factschema"
	iamv1 "github.com/eshu-hq/eshu-sdk/factschema/iam/v1"
)

// NewResourcePolicyPermissionFact builds the durable
// aws_resource_policy_permission fact for one normalized statement from a
// resource-based policy attached to an AWS resource (an S3 bucket policy or
// KMS key policy).
//
// The fact is derived and metadata-only and mirrors the in-tree
// NewResourcePolicyPermissionEnvelope rigor: attached resource identity,
// effect, normalized action/resource patterns, a condition-key summary, and
// derived grantee-principal facts. It NEVER carries the raw policy JSON body,
// the statement Sid (which feeds only the source-record id), or any condition
// values.
func NewResourcePolicyPermissionFact(observation ResourcePolicyPermissionObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(observation.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	resourceARN := strings.TrimSpace(observation.ResourceARN)
	if resourceARN == "" {
		return sdk.Fact{}, fmt.Errorf("aws resource policy permission observation requires resource_arn")
	}
	resourceType := strings.TrimSpace(observation.ResourceType)
	if resourceType == "" {
		return sdk.Fact{}, fmt.Errorf("aws resource policy permission observation requires resource_type")
	}
	effect := normalizeIAMEffect(observation.Effect)
	if effect == "" {
		return sdk.Fact{}, fmt.Errorf("aws resource policy permission observation requires effect")
	}

	actions := normalizeIAMActionList(observation.Actions)
	notActions := normalizeIAMActionList(observation.NotActions)
	resources := normalizeIAMPatternList(observation.Resources)
	notResources := normalizeIAMPatternList(observation.NotResources)
	conditionKeys := normalizeIAMKeyList(observation.ConditionKeys)
	conditionOperators := normalizeIAMKeyList(observation.ConditionOperators)
	principalAccountIDs := normalizeIAMKeyList(observation.PrincipalAccountIDs)
	principalARNs := normalizeIAMPatternList(observation.PrincipalARNs)
	principalTypes := normalizeIAMKeyList(observation.PrincipalTypes)

	statementSID := strings.TrimSpace(observation.StatementSID)

	stableIdentity := map[string]any{
		"account_id":            observation.Boundary.AccountID,
		"actions":               strings.Join(actions, ","),
		"effect":                effect,
		"not_actions":           strings.Join(notActions, ","),
		"not_resources":         strings.Join(notResources, ","),
		"policy_source":         catalog.ResourcePolicySourceResource,
		"principal_account_ids": strings.Join(principalAccountIDs, ","),
		"principal_arns":        strings.Join(principalARNs, ","),
		"region":                observation.Boundary.Region,
		"resource_arn":          resourceARN,
		"resource_type":         resourceType,
		"resources":             strings.Join(resources, ","),
		"statement_sid":         statementSID,
	}
	addConditionSummaryIdentity(stableIdentity, conditionKeys, conditionOperators)
	stableKey, err := specialtyStableKey(AWSKindResourcePolicyPermission, stableIdentity)
	if err != nil {
		return sdk.Fact{}, err
	}

	payload, err := factschema.EncodeAWSResourcePolicyPermission(iamv1.ResourcePolicyPermission{
		AccountID:              observation.Boundary.AccountID,
		Region:                 observation.Boundary.Region,
		ServiceKind:            specialtyBoundaryValue(observation.Boundary.ServiceKind),
		CollectorInstanceID:    specialtyBoundaryValue(observation.Boundary.CollectorInstanceID),
		ResourceARN:            resourceARN,
		ResourceType:           resourceType,
		PolicySource:           specialtyStringPtr(catalog.ResourcePolicySourceResource),
		Effect:                 effect,
		Actions:                actions,
		NotActions:             notActions,
		Resources:              resources,
		NotResources:           notResources,
		ConditionKeys:          conditionKeys,
		ConditionOperators:     conditionOperators,
		ConditionOperatorCount: specialtyIntPtr(len(conditionOperators)),
		PrincipalAccountIDs:    principalAccountIDs,
		PrincipalARNs:          principalARNs,
		PrincipalTypes:         principalTypes,
		HasConditions:          specialtyBoolPtr(len(conditionKeys) > 0 || len(conditionOperators) > 0),
		IsWildcardAction:       specialtyBoolPtr(iamContainsValue(actions, iamPermissionWildcardAction)),
		IsWildcardResource:     specialtyBoolPtr(iamContainsValue(resources, iamPermissionWildcardAction)),
		IsPublic:               specialtyBoolPtr(observation.IsPublic),
		IsCrossAccount:         specialtyBoolPtr(observation.IsCrossAccount),
	})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode aws_resource_policy_permission payload: %w", err)
	}

	recordID := strings.TrimSpace(observation.SourceRecordID)
	if recordID == "" {
		recordID = resourcePolicyPermissionSourceID(resourceARN, resourceType, statementSID, effect, actions)
	}
	return specialtyFact(AWSKindResourcePolicyPermission, stableKey, observation.Boundary, observation.SourceURI, recordID, payload)
}

// resourcePolicyPermissionSourceID builds a deterministic source record id for
// a derived resource-policy statement so repeated observations of the same
// statement map to one durable fact within a generation. The statement Sid is
// part of the id (statements without a Sid fall back to the effect + action
// set) but is never written into the persisted payload.
func resourcePolicyPermissionSourceID(resourceARN, resourceType, statementSID, effect string, actions []string) string {
	parts := []string{resourceARN, resourceType, statementSID, effect, strings.Join(actions, ",")}
	return strings.Join(parts, "#")
}
