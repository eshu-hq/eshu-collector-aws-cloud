// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func TestWarningFactIdentityIncludesOperationResourceEffect(t *testing.T) {
	base := WarningObservation{
		Boundary:    Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2", ScopeID: "aws", GenerationID: "g1", CollectorInstanceID: "collector", ClaimToken: "token", ObservedAt: time.Now().UTC()},
		WarningKind: "permission_denied", ErrorClass: "permission_denied", SourceURI: "aws://123456789012/us-east-1",
		Attributes: map[string]any{"operation": "DescribeSecurityGroupRules", "resource": "region:us-east-1", "effect": "security-group-rules-unavailable"},
	}
	first, err := NewWarningFact(base)
	if err != nil {
		t.Fatal(err)
	}
	if first.Kind != AWSKindWarning || first.SourceRef.FactKey != first.StableKey {
		t.Fatalf("warning fact = %+v", first)
	}
	for _, key := range []string{"operation", "resource", "effect"} {
		variant := base
		variant.Attributes = map[string]any{}
		for k, v := range base.Attributes {
			variant.Attributes[k] = v
		}
		variant.Attributes[key] = "different"
		other, err := NewWarningFact(variant)
		if err != nil {
			t.Fatal(err)
		}
		if other.StableKey == first.StableKey {
			t.Fatalf("%s does not affect identity", key)
		}
	}
	result := sdk.Result{State: sdk.ResultPartial, Claim: sdk.Claim{Scope: sdk.Scope{ID: "aws"}, GenerationID: "g1", InstanceID: "collector", FencingToken: "token"}, Generation: sdk.Generation{ID: "g1", ObservedAt: time.Now().UTC()}, Statuses: []sdk.Status{{Class: sdk.StatusWarning, Partial: true}}}
	result, err = AppendLiveWarnings(result, []WarningObservation{base, base}, base.SourceURI, DefaultResourceUse())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Facts) != 1 || result.Statuses[0].WarningCount != 1 || result.Statuses[0].FactCount != 1 {
		t.Fatalf("result = %+v", result)
	}
}

func TestEmptyOptionalDenialEmitsSDKPartialAndTypedWarning(t *testing.T) {
	sourceURI := "aws://123456789012/us-east-1"
	claim := testClaim()
	opts := CollectOptions{ObservedAt: testObservedAt(), SourceURI: sourceURI}
	result, err := CollectPartial(claim, Report{Source: "aws-live:123456789012/us-east-1"}, opts, "ec2/us-east-1: optional rules denied")
	if err != nil {
		t.Fatal(err)
	}
	warning := WarningObservation{
		Boundary:    Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2"},
		WarningKind: "permission_denied", ErrorClass: "permission_denied",
		Attributes: map[string]any{"operation": "DescribeSecurityGroupRules", "resource": "region:us-east-1", "effect": "security-group-rules-unavailable"},
	}
	result, err = AppendLiveWarnings(result, []WarningObservation{warning}, sourceURI, DefaultResourceUse())
	if err != nil {
		t.Fatal(err)
	}
	typed := 0
	for _, fact := range result.Facts {
		if fact.Kind == AWSKindWarning {
			typed++
		}
	}
	if result.State != sdk.ResultPartial || typed != 1 || len(result.Statuses) < 2 || result.Statuses[len(result.Statuses)-1].Class != sdk.StatusWarning || !result.Statuses[len(result.Statuses)-1].Partial {
		t.Fatalf("empty denied SDK result: state=%s typed=%d statuses=%+v", result.State, typed, result.Statuses)
	}
}
