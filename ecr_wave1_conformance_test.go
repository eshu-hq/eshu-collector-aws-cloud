// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
)

// TestWave1ECRConformance is a schema-admission companion, not the full
// Wave 1 ECR Q4(a) gate: hand-built vectors validate per-kind admission
// against the checked-in JSON Schemas through the public fixture harness,
// using only the published SDK modules. Full Q4(a) proof is
// TestWave1ECRLiveConformance (internal/live/ecr_wave1_conformance_test.go),
// which runs real production-listECR builder output through the same
// harness. The vectors below mirror the shared wave1 fixture rows
// (testdata/wave1-ecr-parity.json); the live parity test proves the same
// builders emit in-tree-identical stable keys (Q4(b)).
func TestWave1ECRConformance(t *testing.T) {
	t.Parallel()

	claim := testClaim()
	observedAt := testObservedAt()
	base := mustCollect(t, "complete.json", claim, observedAt, "")
	sourceURI := "aws://123456789012"

	resources := []ResourceObservation{
		{
			Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ecr"},
			ARN:          "arn:aws:ecr:us-east-1:123456789012:repository/wave1-a",
			ResourceID:   "arn:aws:ecr:us-east-1:123456789012:repository/wave1-a",
			ResourceType: "aws_ecr_repository",
			Name:         "wave1-a",
			Attributes: map[string]any{
				"image_tag_mutability": "IMMUTABLE",
				"repository_uri":       "123456789012.dkr.ecr.us-east-1.amazonaws.com/wave1-a",
				"scan_on_push":         true,
			},
			CorrelationAnchors: []string{
				"arn:aws:ecr:us-east-1:123456789012:repository/wave1-a",
				"123456789012.dkr.ecr.us-east-1.amazonaws.com/wave1-a",
				"wave1-a",
			},
			SourceRecordID: "arn:aws:ecr:us-east-1:123456789012:repository/wave1-a",
		},
		{
			Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ecr"},
			ResourceID:   "arn:aws:ecr:us-east-1:123456789012:repository/wave1-a#lifecycle-policy",
			ResourceType: "aws_ecr_lifecycle_policy",
			Name:         "wave1-a:lifecycle-policy",
			Attributes: map[string]any{
				"parent_repository_arn":  "arn:aws:ecr:us-east-1:123456789012:repository/wave1-a",
				"parent_repository_name": "wave1-a",
				"registry_id":            "123456789012",
			},
			CorrelationAnchors: []string{
				"arn:aws:ecr:us-east-1:123456789012:repository/wave1-a#lifecycle-policy",
				"arn:aws:ecr:us-east-1:123456789012:repository/wave1-a",
				"wave1-a",
			},
			SourceRecordID: "arn:aws:ecr:us-east-1:123456789012:repository/wave1-a#lifecycle-policy",
		},
	}
	images := []ImageReferenceObservation{
		{
			Boundary:       Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ecr"},
			RepositoryARN:  "arn:aws:ecr:us-east-1:123456789012:repository/wave1-a",
			RepositoryName: "wave1-a",
			RegistryID:     "123456789012",
			ImageDigest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Tag:            "latest",
		},
	}

	result := base
	var err error
	result, err = AppendLiveResources(result, resources, sourceURI, ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	result, err = AppendLiveImageReferences(result, images, sourceURI, ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected wave1 ECR result: %v", err)
	}
	report := conformance.Run(coreFixtureRequest(t, loadManifest(t), []sdk.Result{result}))
	if !report.OK() {
		t.Fatalf("wave1 ECR conformance findings = %#v, want passed", report.Findings)
	}
}
