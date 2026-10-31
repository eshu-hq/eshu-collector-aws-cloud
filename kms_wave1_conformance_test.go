// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
)

// TestWave1KMSConformance is a schema-admission companion, not the full
// Wave 1 KMS Q4(a) gate: hand-built vectors validate per-kind admission
// against the checked-in JSON Schemas through the public fixture harness,
// using only the published SDK modules. Full Q4(a) proof is
// TestWave1KMSLiveConformance (internal/live/kms_wave1_conformance_test.go),
// which runs real production-listKMS builder output through the same
// harness. The vectors below mirror the shared wave1 fixture rows
// (testdata/wave1-kms-parity.json); the live parity test proves the same
// builders emit in-tree-identical stable keys (Q4(b)).
func TestWave1KMSConformance(t *testing.T) {
	t.Parallel()

	claim := testClaim()
	observedAt := testObservedAt()
	base := mustCollect(t, "complete.json", claim, observedAt, "")
	sourceURI := "aws://123456789012"

	resources := []ResourceObservation{
		{
			Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "kms"},
			ARN:          "arn:aws:kms:us-east-1:123456789012:key/a1b2c3d4-e5f6-4789-abcd-ef0123456789",
			ResourceID:   "a1b2c3d4-e5f6-4789-abcd-ef0123456789",
			ResourceType: "aws_kms_key",
			Name:         "a1b2c3d4-e5f6-4789-abcd-ef0123456789",
			State:        "Enabled",
			Attributes: map[string]any{
				"key_manager": "CUSTOMER",
				"key_usage":   "ENCRYPT_DECRYPT",
				"key_spec":    "SYMMETRIC_DEFAULT",
				"key_state":   "Enabled",
				"origin":      "AWS_KMS",
				"enabled":     true,
			},
			CorrelationAnchors: []string{
				"arn:aws:kms:us-east-1:123456789012:key/a1b2c3d4-e5f6-4789-abcd-ef0123456789",
				"a1b2c3d4-e5f6-4789-abcd-ef0123456789",
			},
			SourceRecordID: "arn:aws:kms:us-east-1:123456789012:key/a1b2c3d4-e5f6-4789-abcd-ef0123456789",
		},
		{
			Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "kms"},
			ARN:          "arn:aws:kms:us-east-1:123456789012:alias/wave1-a",
			ResourceID:   "arn:aws:kms:us-east-1:123456789012:alias/wave1-a",
			ResourceType: "aws_kms_alias",
			Name:         "alias/wave1-a",
			Attributes: map[string]any{
				"alias_name":    "alias/wave1-a",
				"target_key_id": "a1b2c3d4-e5f6-4789-abcd-ef0123456789",
				"last_updated":  "2026-02-01T12:00:00Z",
			},
			CorrelationAnchors: []string{
				"arn:aws:kms:us-east-1:123456789012:alias/wave1-a", "alias/wave1-a",
			},
			SourceRecordID: "arn:aws:kms:us-east-1:123456789012:alias/wave1-a",
		},
		{
			Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "kms"},
			ResourceID:   "a1b2c3d4-e5f6-4789-abcd-ef0123456789/grant/grant-a1",
			ResourceType: "aws_kms_grant",
			Name:         "wave1-grant",
			Attributes: map[string]any{
				"grant_id":           "grant-a1",
				"grant_name":         "wave1-grant",
				"key_id":             "a1b2c3d4-e5f6-4789-abcd-ef0123456789",
				"grantee_principal":  "arn:aws:iam::123456789012:role/wave1-app",
				"retiring_principal": "arn:aws:iam::123456789012:role/wave1-admin",
				"issuing_account":    "123456789012",
				"operations":         []string{"Encrypt", "Decrypt", "GenerateDataKey"},
			},
			CorrelationAnchors: []string{
				"grant-a1", "a1b2c3d4-e5f6-4789-abcd-ef0123456789/grant/grant-a1",
			},
			SourceRecordID: "a1b2c3d4-e5f6-4789-abcd-ef0123456789/grant/grant-a1",
		},
	}
	relationships := []RelationshipObservation{
		{
			Boundary:         Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "kms"},
			RelationshipType: "kms_alias_targets_key",
			SourceResourceID: "arn:aws:kms:us-east-1:123456789012:alias/wave1-a",
			SourceARN:        "arn:aws:kms:us-east-1:123456789012:alias/wave1-a",
			TargetResourceID: "a1b2c3d4-e5f6-4789-abcd-ef0123456789",
			TargetARN:        "arn:aws:kms:us-east-1:123456789012:key/a1b2c3d4-e5f6-4789-abcd-ef0123456789",
			TargetType:       "aws_kms_key",
			SourceRecordID:   "arn:aws:kms:us-east-1:123456789012:alias/wave1-a->a1b2c3d4-e5f6-4789-abcd-ef0123456789",
		},
		{
			Boundary:         Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "kms"},
			RelationshipType: "kms_grant_on_key",
			SourceResourceID: "a1b2c3d4-e5f6-4789-abcd-ef0123456789/grant/grant-a1",
			TargetResourceID: "a1b2c3d4-e5f6-4789-abcd-ef0123456789",
			TargetARN:        "arn:aws:kms:us-east-1:123456789012:key/a1b2c3d4-e5f6-4789-abcd-ef0123456789",
			TargetType:       "aws_kms_key",
			SourceRecordID:   "a1b2c3d4-e5f6-4789-abcd-ef0123456789/grant/grant-a1->a1b2c3d4-e5f6-4789-abcd-ef0123456789",
		},
		{
			Boundary:         Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "kms"},
			RelationshipType: "kms_grant_for_grantee",
			SourceResourceID: "a1b2c3d4-e5f6-4789-abcd-ef0123456789/grant/grant-a1",
			TargetResourceID: "AWS:arn:aws:iam::123456789012:role/wave1-app",
			TargetARN:        "arn:aws:iam::123456789012:role/wave1-app",
			TargetType:       "aws_iam_principal",
			SourceRecordID:   "a1b2c3d4-e5f6-4789-abcd-ef0123456789/grant/grant-a1->AWS:arn:aws:iam::123456789012:role/wave1-app",
		},
	}

	result := base
	var err error
	result, err = AppendLiveResources(result, resources, sourceURI, ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	result, err = AppendLiveRelationships(result, relationships, sourceURI, ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected wave1 KMS result: %v", err)
	}
	report := conformance.Run(coreFixtureRequest(t, loadManifest(t), []sdk.Result{result}))
	if !report.OK() {
		t.Fatalf("wave1 KMS conformance findings = %#v, want passed", report.Findings)
	}
}
