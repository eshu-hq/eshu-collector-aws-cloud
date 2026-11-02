// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"fmt"
	"strings"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// AppendLiveDNSRecords adds claim-bound Route 53 record observations under
// fact budgets. The live Route 53 reader sets one observation per supported
// ListResourceRecordSets row; unsupported rows stay transitional records.
func AppendLiveDNSRecords(result sdk.Result, observations []DNSRecordObservation, sourceURI string, limits ResourceUse) (sdk.Result, error) {
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
		fact, err := NewDNSRecordFact(observation)
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
			return sdk.Result{}, fmt.Errorf("encode live DNS record payload: %w", err)
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
