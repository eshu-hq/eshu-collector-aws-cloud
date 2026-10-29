// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// A synthetic declaration checks SDK result validation; it is not a host grant.
func TestResourceFactPassesSDKResultValidation(t *testing.T) {
	observation := resourceParityObservation(t)
	fact, err := NewResourceFact(observation)
	if err != nil {
		t.Fatal(err)
	}
	claim := testClaim()
	claim.Scope.ID = observation.Boundary.ScopeID
	claim.GenerationID = observation.Boundary.GenerationID
	result := sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultComplete,
		Claim:           claim,
		Generation: sdk.Generation{
			ID: observation.Boundary.GenerationID, ObservedAt: observation.Boundary.ObservedAt,
		},
		Facts: []sdk.Fact{fact},
	}
	validator := sdk.NewValidator(sdk.Contract{Facts: []sdk.FactDeclaration{{
		Kind: AWSKindResource, SchemaVersions: []string{"1.0.0"},
		SourceConfidence: []sdk.SourceConfidence{sdk.SourceConfidenceReported},
	}}})
	if _, err := validator.ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected constructed resource fact: %v", err)
	}
}
