// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// TestWave1EC2PipelineFansOutPostures proves the fan-out wiring the key
// parity tests cannot see: record posture fields flow through CollectReport
// into Outcome slices and through AppendOutcomeFacts — the same shared
// function cmd/collector/collectLivePlan calls — into validated facts. The
// loader feeds one rule row and one instance row through the real production
// builders; no network is touched. Omitting an appender from the shared
// sequence fails the assertions here instead of silently dropping the
// posture kinds in production.
func TestWave1EC2PipelineFansOutPostures(t *testing.T) {
	t.Parallel()

	fixture := loadWave1EC2Fixture(t)
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	loader := func(context.Context, aws.Config, VerifiedIdentity) ([]collector.Record, error) {
		rule, err := securityGroupRuleRecord(wave1SDKRules(t, fixture)[0], "us-east-1")
		if err != nil {
			return nil, err
		}
		records := []collector.Record{rule}
		instance, err := appendInstanceRecords(nil, wave1SDKInstance(t, fixture), "us-east-1", identity, map[string]struct{}{})
		if err != nil {
			return nil, err
		}
		return append(records, instance...), nil
	}
	reader := Collector{
		LoadConfig: func(context.Context, string) (aws.Config, error) {
			return aws.Config{Region: "us-east-1"}, nil
		},
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return identity, nil
		},
		Loaders: map[string]Loader{"ec2": loader},
	}
	outcome, err := reader.CollectReport(context.Background(), Config{
		AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"ec2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Resources) != 3 || len(outcome.Relationships) != 2 ||
		len(outcome.SGPostures) != 1 || len(outcome.EC2Postures) != 1 {
		t.Fatalf("outcome = %d resources %d relationships %d SG postures %d EC2 postures, want 3/2/1/1",
			len(outcome.Resources), len(outcome.Relationships), len(outcome.SGPostures), len(outcome.EC2Postures))
	}

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
	sourceURI := "aws:ec2:us-east-1:wave1-parity"
	limits := collector.DefaultResourceUse()
	// Production path: the exact shared function collectLivePlan calls.
	if result, err = AppendOutcomeFacts(result, outcome, sourceURI, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.NewValidator(collector.Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected pipeline result built from real builder output: %v", err)
	}
	want := map[string]bool{
		"aws_security_group_rule\x00d4373b5d54f28e24d86164a999d1b4413957f5725e869980ef33d1ae57c88c8b": false,
		"ec2_instance_posture\x00bccfe99d717602531c9eeb0ac1889236f16e0924ffc40b66ff8fefee72e81b04":    false,
	}
	for _, fact := range result.Facts {
		if _, ok := want[fact.Kind+"\x00"+fact.StableKey]; ok {
			want[fact.Kind+"\x00"+fact.StableKey] = true
		}
	}
	for key, found := range want {
		if !found {
			t.Errorf("pipeline result missing oracle fact %q", key)
		}
	}
}
