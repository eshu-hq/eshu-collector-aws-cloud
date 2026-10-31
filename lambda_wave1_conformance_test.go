// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
)

// TestWave1LambdaConformance is a schema-admission companion, not the full
// Wave 1 Lambda Q4(a) gate: hand-built vectors validate per-kind admission
// against the checked-in JSON Schemas through the public fixture harness,
// using only the published SDK modules. Full Q4(a) proof is
// TestWave1LambdaLiveConformance (internal/live/lambda_wave1_conformance_test.go),
// which runs real production-listLambda builder output through the same
// harness. The vectors below mirror the shared wave1 fixture rows
// (testdata/wave1-lambda-parity.json); the live parity test proves the same
// builders emit in-tree-identical stable keys (Q4(b)).
func TestWave1LambdaConformance(t *testing.T) {
	t.Parallel()

	claim := testClaim()
	observedAt := testObservedAt()
	base := mustCollect(t, "complete.json", claim, observedAt, "")
	sourceURI := "aws://123456789012"

	resources := []ResourceObservation{
		{
			Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "lambda"},
			ARN:          "arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
			ResourceID:   "arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
			ResourceType: "aws_lambda_function",
			Name:         "wave1-a",
			State:        "Active",
			Attributes: map[string]any{
				"handler":  "index.handler",
				"runtime":  "python3.12",
				"role_arn": "arn:aws:iam::123456789012:role/wave1-lambda-role",
			},
			CorrelationAnchors: []string{
				"arn:aws:lambda:us-east-1:123456789012:function:wave1-a", "wave1-a",
			},
			SourceRecordID: "arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
		},
		{
			Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "lambda"},
			ARN:          "arn:aws:lambda:us-east-1:123456789012:function:wave1-a:live",
			ResourceID:   "arn:aws:lambda:us-east-1:123456789012:function:wave1-a:live",
			ResourceType: "aws_lambda_alias",
			Name:         "live",
			Attributes: map[string]any{
				"function_arn":     "arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
				"function_version": "5",
			},
			CorrelationAnchors: []string{
				"arn:aws:lambda:us-east-1:123456789012:function:wave1-a:live",
				"live",
				"arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
			},
			SourceRecordID: "arn:aws:lambda:us-east-1:123456789012:function:wave1-a:live",
		},
		{
			Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "lambda"},
			ARN:          "arn:aws:lambda:us-east-1:123456789012:event-source-mapping:11111111-2222-3333-4444-555555555555",
			ResourceID:   "arn:aws:lambda:us-east-1:123456789012:event-source-mapping:11111111-2222-3333-4444-555555555555",
			ResourceType: "aws_lambda_event_source_mapping",
			Name:         "11111111-2222-3333-4444-555555555555",
			State:        "Enabled",
			Attributes: map[string]any{
				"batch_size":       int32(10),
				"event_source_arn": "arn:aws:sqs:us-east-1:123456789012:wave1-events",
				"function_arn":     "arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
				"uuid":             "11111111-2222-3333-4444-555555555555",
			},
			CorrelationAnchors: []string{
				"arn:aws:lambda:us-east-1:123456789012:event-source-mapping:11111111-2222-3333-4444-555555555555",
				"arn:aws:sqs:us-east-1:123456789012:wave1-events",
				"arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
			},
			SourceRecordID: "arn:aws:lambda:us-east-1:123456789012:event-source-mapping:11111111-2222-3333-4444-555555555555",
		},
	}
	relationships := []RelationshipObservation{
		{
			Boundary:         Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "lambda"},
			RelationshipType: "lambda_function_uses_execution_role",
			SourceResourceID: "arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
			SourceARN:        "arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
			TargetResourceID: "arn:aws:iam::123456789012:role/wave1-lambda-role",
			TargetARN:        "arn:aws:iam::123456789012:role/wave1-lambda-role",
			TargetType:       "aws_iam_role",
			SourceRecordID:   "arn:aws:lambda:us-east-1:123456789012:function:wave1-a#execution-role#arn:aws:iam::123456789012:role/wave1-lambda-role",
		},
		{
			Boundary:         Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "lambda"},
			RelationshipType: "lambda_alias_targets_function",
			SourceResourceID: "arn:aws:lambda:us-east-1:123456789012:function:wave1-a:live",
			SourceARN:        "arn:aws:lambda:us-east-1:123456789012:function:wave1-a:live",
			TargetResourceID: "arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
			TargetARN:        "arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
			TargetType:       "aws_lambda_function",
			Attributes:       map[string]any{"function_version": "5"},
			SourceRecordID:   "arn:aws:lambda:us-east-1:123456789012:function:wave1-a:live#function#arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
		},
		{
			Boundary:         Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "lambda"},
			RelationshipType: "lambda_event_source_mapping_targets_function",
			SourceResourceID: "arn:aws:lambda:us-east-1:123456789012:event-source-mapping:11111111-2222-3333-4444-555555555555",
			SourceARN:        "arn:aws:lambda:us-east-1:123456789012:event-source-mapping:11111111-2222-3333-4444-555555555555",
			TargetResourceID: "arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
			TargetARN:        "arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
			TargetType:       "aws_lambda_function",
			Attributes: map[string]any{
				"event_source_arn": "arn:aws:sqs:us-east-1:123456789012:wave1-events",
				"state":            "Enabled",
				"uuid":             "11111111-2222-3333-4444-555555555555",
			},
			SourceRecordID: "arn:aws:lambda:us-east-1:123456789012:event-source-mapping:11111111-2222-3333-4444-555555555555#function#arn:aws:lambda:us-east-1:123456789012:function:wave1-a",
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
		t.Fatalf("SDK rejected wave1 Lambda result: %v", err)
	}
	report := conformance.Run(coreFixtureRequest(t, harnessView(loadManifest(t)), []sdk.Result{result}))
	if !report.OK() {
		t.Fatalf("wave1 Lambda conformance findings = %#v, want passed", report.Findings)
	}
}
