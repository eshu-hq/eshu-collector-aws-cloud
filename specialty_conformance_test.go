// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
)

// TestSpecialtySeamConformance is the Wave 0 Q4(a) gate: every specialty kind
// the seam emits validates against its checked-in JSON Schema through the
// public fixture harness, using only the published SDK modules. One fact per
// kind comes straight from the parity fixtures via the seam builders, so this
// test proves schema-valid emission end to end, not just encoder output.
func TestSpecialtySeamConformance(t *testing.T) {
	t.Parallel()

	claim := testClaim()
	observedAt := testObservedAt()

	// The SDK validator binds every fact's scope/generation/instance to the
	// claim. Re-scope the parity observations onto this claim: no specialty
	// stable-key identity includes scope, generation, or instance, so keys
	// are unchanged (asserted below for the DNS fact), and schema validity
	// does not depend on the claim triple.
	rescope := func(boundary Boundary) Boundary {
		boundary.ScopeID = claim.Scope.ID
		boundary.GenerationID = claim.GenerationID
		boundary.CollectorInstanceID = claim.InstanceID
		boundary.ObservedAt = observedAt
		return boundary
	}

	dnsObservation := dnsParityObservation(t)
	dnsObservation.Boundary = rescope(dnsObservation.Boundary)
	dnsFact, err := NewDNSRecordFact(dnsObservation)
	if err != nil {
		t.Fatal(err)
	}
	if dnsFact.StableKey != frozenDNSRecordKey {
		t.Fatalf("rescoped StableKey = %q, want frozen %q (keys are claim-independent)",
			dnsFact.StableKey, frozenDNSRecordKey)
	}
	sgObservation := sgRuleParityObservation(t)
	sgObservation.Boundary = rescope(sgObservation.Boundary)
	sgFact, err := NewSecurityGroupRuleFact(sgObservation)
	if err != nil {
		t.Fatal(err)
	}
	iamObservation, _ := iamParityObservation(t)
	iamObservation.Boundary = rescope(iamObservation.Boundary)
	iamFact, err := NewIAMPermissionFact(iamObservation)
	if err != nil {
		t.Fatal(err)
	}
	resourcePolicyObservation := resourcePolicyParityObservation(t)
	resourcePolicyObservation.Boundary = rescope(resourcePolicyObservation.Boundary)
	resourcePolicyFact, err := NewResourcePolicyPermissionFact(resourcePolicyObservation)
	if err != nil {
		t.Fatal(err)
	}
	ec2Observation := ec2PostureParityObservation(t)
	ec2Observation.Boundary = rescope(ec2Observation.Boundary)
	ec2Fact, err := NewEC2InstancePostureFact(ec2Observation)
	if err != nil {
		t.Fatal(err)
	}
	rdsObservation := rdsPostureParityObservation(t)
	rdsObservation.Boundary = rescope(rdsObservation.Boundary)
	rdsFact, err := NewRDSInstancePostureFact(rdsObservation)
	if err != nil {
		t.Fatal(err)
	}
	grantObservation := s3GrantParityObservation(t)
	grantObservation.Boundary = rescope(grantObservation.Boundary)
	grantFact, err := NewS3ExternalPrincipalGrantFact(grantObservation)
	if err != nil {
		t.Fatal(err)
	}
	result := sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultComplete,
		Claim:           claim,
		Generation:      sdk.Generation{ID: claim.GenerationID, ObservedAt: observedAt},
		Facts:           []sdk.Fact{dnsFact, sgFact, iamFact, resourcePolicyFact, ec2Fact, rdsFact, grantFact},
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected specialty result: %v", err)
	}
	report := conformance.Run(coreFixtureRequest(t, loadManifest(t), []sdk.Result{result}))
	if !report.OK() {
		t.Fatalf("specialty conformance findings = %#v, want passed", report.Findings)
	}
	if report.Summary.FactCount != len(result.Facts) {
		t.Fatalf("FactCount = %d, want %d", report.Summary.FactCount, len(result.Facts))
	}
}
