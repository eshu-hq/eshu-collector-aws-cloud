// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"
	"time"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
)

// TestWave1EC2BuilderConformance is the Wave 1 EC2 Q4(a) gate over real
// builder output: every posture fact the production EC2 builders emit for the
// shared fixture (all three rule rows including the legacy blank-rule-id and
// nil-port prefix-list fallback shapes, plus the instance row) validates
// against its checked-in JSON Schema through the SDK validator and the
// conformance harness. The root TestWave1EC2Conformance guards only
// hand-built vectors; this test guards the builder-derived edge cases that
// gate cannot see. The companion gap test proves the same facts carry
// in-tree-identical stable keys (Q4(b)).
func TestWave1EC2BuilderConformance(t *testing.T) {
	t.Parallel()

	fixture := loadWave1EC2Fixture(t)
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	const accountID = "123456789012"

	observedAt := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	result := sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultComplete,
		Claim: sdk.Claim{
			ComponentID: collector.ComponentID, InstanceID: "aws-parity-wave1",
			CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem,
			Scope:       sdk.Scope{ID: "aws:123456789012:us-east-1", Kind: "component"},
			SourceRunID: "wave1-parity-run", GenerationID: "aws:123456789012:us-east-1:wave1:1",
			WorkItemID: "wave1-parity-work", FencingToken: "wave1-parity-token",
			Attempt: 1, Deadline: observedAt.Add(time.Hour), ConfigHandle: "component-config:aws-cloud",
		},
		Generation: sdk.Generation{ID: "aws:123456789012:us-east-1:wave1:1", ObservedAt: observedAt},
	}

	sgKinds := map[string]bool{}
	for _, rule := range wave1SDKRules(t, fixture) {
		row, err := securityGroupRuleRecord(rule, "us-east-1")
		if err != nil {
			t.Fatal(err)
		}
		if row.SGPosture == nil {
			t.Fatal("security group rule record carries no posture observation")
		}
		posture := *row.SGPosture
		posture.Boundary = wave1Boundary(accountID, "us-east-1", "ec2")
		posture.SourceURI = "aws:ec2:us-east-1:wave1-parity"
		fact, err := collector.NewSecurityGroupRuleFact(posture)
		if err != nil {
			t.Fatal(err)
		}
		result.Facts = append(result.Facts, fact)
		sgKinds[fact.StableKey] = true
	}

	ec2Kinds := map[string]bool{}
	instanceRecords, err := appendInstanceRecords(nil, wave1SDKInstance(t, fixture), "us-east-1", identity, map[string]struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range instanceRecords {
		if record.EC2Posture == nil {
			continue
		}
		posture := *record.EC2Posture
		posture.Boundary = wave1Boundary(accountID, "us-east-1", "ec2")
		posture.SourceURI = "aws:ec2:us-east-1:wave1-parity"
		fact, err := collector.NewEC2InstancePostureFact(posture)
		if err != nil {
			t.Fatal(err)
		}
		result.Facts = append(result.Facts, fact)
		ec2Kinds[fact.StableKey] = true
	}

	if len(result.Facts) != 4 || len(sgKinds) != 3 || len(ec2Kinds) != 1 {
		t.Fatalf("builder facts = %d total %d SG %d EC2, want 4/3/1",
			len(result.Facts), len(sgKinds), len(ec2Kinds))
	}
	if _, err := sdk.NewValidator(collector.Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected builder-derived wave1 EC2 result: %v", err)
	}
	report := conformance.Run(wave1ConformanceRequest(t, []sdk.Result{result}))
	if !report.OK() {
		t.Fatalf("builder-derived wave1 EC2 conformance findings = %#v, want passed", report.Findings)
	}
}
