// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
)

// TestWave1SSMConformance is a schema-admission companion, not the full
// Wave 1 SSM Q4(a) gate: hand-built vectors validate per-kind admission
// against the checked-in JSON Schemas through the public fixture harness,
// using only the published SDK modules. Full Q4(a) proof is
// TestWave1SSMLiveConformance (internal/live/ssm_wave1_conformance_test.go),
// which runs real production-listSSM builder output through the same
// harness. The vectors below mirror the shared wave1 fixture rows
// (testdata/wave1-ssm-parity.json); the live parity test proves the same
// builders emit in-tree-identical stable keys (Q4(b)).
func TestWave1SSMConformance(t *testing.T) {
	t.Parallel()

	claim := testClaim()
	observedAt := testObservedAt()
	base := mustCollect(t, "complete.json", claim, observedAt, "")
	sourceURI := "aws://123456789012"

	resources := []ResourceObservation{
		{
			Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ssm"},
			ARN:          "arn:aws:ssm:us-east-1:123456789012:parameter/wave1/db/password",
			ResourceID:   "arn:aws:ssm:us-east-1:123456789012:parameter/wave1/db/password",
			ResourceType: "aws_ssm_parameter",
			Name:         "/wave1/db/password",
			Attributes: map[string]any{
				"data_type":               "text",
				"key_id":                  "arn:aws:kms:us-east-1:123456789012:key/wave1-key-1",
				"tier":                    "Advanced",
				"type":                    "SecureString",
				"description_present":     true,
				"allowed_pattern_present": true,
			},
			CorrelationAnchors: []string{
				"arn:aws:ssm:us-east-1:123456789012:parameter/wave1/db/password", "/wave1/db/password",
			},
			SourceRecordID: "arn:aws:ssm:us-east-1:123456789012:parameter/wave1/db/password",
		},
	}
	relationships := []RelationshipObservation{
		{
			Boundary:         Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ssm"},
			RelationshipType: "ssm_parameter_uses_kms_key",
			SourceResourceID: "arn:aws:ssm:us-east-1:123456789012:parameter/wave1/db/password",
			SourceARN:        "arn:aws:ssm:us-east-1:123456789012:parameter/wave1/db/password",
			TargetResourceID: "arn:aws:kms:us-east-1:123456789012:key/wave1-key-1",
			TargetARN:        "arn:aws:kms:us-east-1:123456789012:key/wave1-key-1",
			TargetType:       "aws_kms_key",
			SourceRecordID:   "arn:aws:ssm:us-east-1:123456789012:parameter/wave1/db/password->ssm_parameter_uses_kms_key:arn:aws:kms:us-east-1:123456789012:key/wave1-key-1",
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
		t.Fatalf("SDK rejected wave1 SSM result: %v", err)
	}
	report := conformance.Run(coreFixtureRequest(t, loadManifest(t), []sdk.Result{result}))
	if !report.OK() {
		t.Fatalf("wave1 SSM conformance findings = %#v, want passed", report.Findings)
	}
}
