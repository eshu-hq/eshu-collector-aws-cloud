// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// AppendLiveResources adds typed AWS observations to a claim-bound live result.
// The source loader supplies resource identity; the host claim supplies scope,
// generation, and its opaque fencing token. The token never enters a fact.
func AppendLiveResources(result sdk.Result, resources []ResourceObservation, sourceURI string, limits ResourceUse) (sdk.Result, error) {
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
	seen := make(map[string]struct{}, len(result.Facts)+len(resources))
	for _, fact := range result.Facts {
		seen[fact.Kind+"\x00"+fact.StableKey] = struct{}{}
	}
	for _, resource := range resources {
		resource.Boundary.ScopeID = result.Claim.Scope.ID
		resource.Boundary.GenerationID = result.Claim.GenerationID
		resource.Boundary.CollectorInstanceID = result.Claim.InstanceID
		resource.Boundary.ClaimToken = result.Claim.FencingToken
		resource.Boundary.ObservedAt = result.Generation.ObservedAt
		resource.SourceURI = sourceURI
		if strings.TrimSpace(resource.SourceRecordID) == "" {
			resource.SourceRecordID = resource.ResourceID
		}
		fact, err := NewResourceFact(resource)
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
			return sdk.Result{}, errors.New("encode live AWS resource payload failed")
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
