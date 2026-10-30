// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"fmt"
	"strings"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// AppendLiveSecurityGroupRulePostures adds claim-bound security-group rule
// posture facts under fact budgets. It mirrors AppendLiveS3BucketPostures:
// the live EC2 reader supplies the observation, the host claim supplies
// scope, generation, and its opaque fencing token.
func AppendLiveSecurityGroupRulePostures(result sdk.Result, observations []SecurityGroupRuleObservation, sourceURI string, limits ResourceUse) (sdk.Result, error) {
	if result.State != sdk.ResultComplete && result.State != sdk.ResultPartial {
		return result, nil
	}
	if limits.MaxRecordsPerClaim <= 0 {
		limits.MaxRecordsPerClaim = DefaultResourceUse().MaxRecordsPerClaim
	}
	if limits.MaxPayloadBytes <= 0 {
		limits.MaxPayloadBytes = DefaultResourceUse().MaxPayloadBytes
	}
	if strings.TrimSpace(result.Claim.FencingToken) == "" {
		return sdk.Result{}, fmt.Errorf("live AWS claim requires fencing token")
	}
	seen := make(map[string]struct{}, len(result.Facts)+len(observations))
	for _, fact := range result.Facts {
		seen[fact.Kind+"\x00"+fact.StableKey] = struct{}{}
	}
	for _, observation := range observations {
		observation.Boundary.ScopeID = result.Claim.Scope.ID
		observation.Boundary.GenerationID = result.Claim.GenerationID
		observation.Boundary.CollectorInstanceID = result.Claim.InstanceID
		observation.Boundary.ClaimToken = result.Claim.FencingToken
		observation.Boundary.ObservedAt = result.Generation.ObservedAt
		observation.SourceURI = sourceURI
		fact, err := NewSecurityGroupRuleFact(observation)
		if err != nil {
			return sdk.Result{}, err
		}
		key := fact.Kind + "\x00" + fact.StableKey
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		if len(result.Facts) >= limits.MaxRecordsPerClaim {
			return terminalResult(result.Claim, result.Generation.ObservedAt, "record-budget-exceeded"), nil
		}
		encoded, err := json.Marshal(fact.Payload)
		if err != nil {
			return sdk.Result{}, fmt.Errorf("encode live security group rule posture payload: %w", err)
		}
		if len(encoded) > limits.MaxPayloadBytes {
			return terminalResult(result.Claim, result.Generation.ObservedAt, "payload-budget-exceeded"), nil
		}
		result.Facts = append(result.Facts, fact)
	}
	for index := range result.Statuses {
		result.Statuses[index].FactCount = len(result.Facts)
	}
	return result, nil
}

// AppendLiveEC2InstancePostures adds claim-bound instance posture facts under
// fact budgets, following the same claim-binding contract.
func AppendLiveEC2InstancePostures(result sdk.Result, observations []EC2InstancePostureObservation, sourceURI string, limits ResourceUse) (sdk.Result, error) {
	if result.State != sdk.ResultComplete && result.State != sdk.ResultPartial {
		return result, nil
	}
	if limits.MaxRecordsPerClaim <= 0 {
		limits.MaxRecordsPerClaim = DefaultResourceUse().MaxRecordsPerClaim
	}
	if limits.MaxPayloadBytes <= 0 {
		limits.MaxPayloadBytes = DefaultResourceUse().MaxPayloadBytes
	}
	if strings.TrimSpace(result.Claim.FencingToken) == "" {
		return sdk.Result{}, fmt.Errorf("live AWS claim requires fencing token")
	}
	seen := make(map[string]struct{}, len(result.Facts)+len(observations))
	for _, fact := range result.Facts {
		seen[fact.Kind+"\x00"+fact.StableKey] = struct{}{}
	}
	for _, observation := range observations {
		observation.Boundary.ScopeID = result.Claim.Scope.ID
		observation.Boundary.GenerationID = result.Claim.GenerationID
		observation.Boundary.CollectorInstanceID = result.Claim.InstanceID
		observation.Boundary.ClaimToken = result.Claim.FencingToken
		observation.Boundary.ObservedAt = result.Generation.ObservedAt
		observation.SourceURI = sourceURI
		fact, err := NewEC2InstancePostureFact(observation)
		if err != nil {
			return sdk.Result{}, err
		}
		key := fact.Kind + "\x00" + fact.StableKey
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		if len(result.Facts) >= limits.MaxRecordsPerClaim {
			return terminalResult(result.Claim, result.Generation.ObservedAt, "record-budget-exceeded"), nil
		}
		encoded, err := json.Marshal(fact.Payload)
		if err != nil {
			return sdk.Result{}, fmt.Errorf("encode live EC2 instance posture payload: %w", err)
		}
		if len(encoded) > limits.MaxPayloadBytes {
			return terminalResult(result.Claim, result.Generation.ObservedAt, "payload-budget-exceeded"), nil
		}
		result.Facts = append(result.Facts, fact)
	}
	for index := range result.Statuses {
		result.Statuses[index].FactCount = len(result.Facts)
	}
	return result, nil
}
