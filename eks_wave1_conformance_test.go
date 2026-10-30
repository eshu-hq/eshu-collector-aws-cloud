// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
)

// TestWave1EKSConformance is the Wave 1 EKS Q4(a) gate: every kind the
// completed EKS live path emits validates against its checked-in JSON Schema
// through the public fixture harness, using only the published SDK modules.
// The vectors below mirror the shared wave1 fixture rows
// (testdata/wave1-eks-parity.json); the live parity test proves the same
// builders emit in-tree-identical stable keys (Q4(b)).
func TestWave1EKSConformance(t *testing.T) {
	t.Parallel()

	claim := testClaim()
	observedAt := testObservedAt()
	base := mustCollect(t, "complete.json", claim, observedAt, "")
	sourceURI := "aws://123456789012"

	resources := []ResourceObservation{
		{
			Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "eks"},
			ARN:          "arn:aws:eks:us-east-1:123456789012:cluster/wave1-a",
			ResourceID:   "arn:aws:eks:us-east-1:123456789012:cluster/wave1-a",
			ResourceType: "aws_eks_cluster",
			Name:         "wave1-a",
			State:        "ACTIVE",
			Attributes: map[string]any{
				"version":          "1.29",
				"platform_version": "eks.1",
				"role_arn":         "arn:aws:iam::123456789012:role/wave1-eks-role",
			},
			CorrelationAnchors: []string{
				"arn:aws:eks:us-east-1:123456789012:cluster/wave1-a", "wave1-a",
			},
			SourceRecordID: "arn:aws:eks:us-east-1:123456789012:cluster/wave1-a",
		},
		{
			Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "eks"},
			ARN:          "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/WAVE1AAA",
			ResourceID:   "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/WAVE1AAA",
			ResourceType: "aws_eks_oidc_provider",
			Name:         "https://oidc.eks.us-east-1.amazonaws.com/id/WAVE1AAA",
			Attributes: map[string]any{
				"cluster_arn":  "arn:aws:eks:us-east-1:123456789012:cluster/wave1-a",
				"cluster_name": "wave1-a",
				"issuer_url":   "https://oidc.eks.us-east-1.amazonaws.com/id/WAVE1AAA",
			},
			CorrelationAnchors: []string{
				"arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/WAVE1AAA",
				"https://oidc.eks.us-east-1.amazonaws.com/id/WAVE1AAA",
				"wave1-a",
			},
			SourceRecordID: "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/WAVE1AAA",
		},
	}
	relationships := []RelationshipObservation{
		{
			Boundary:         Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "eks"},
			RelationshipType: "eks_cluster_has_oidc_provider",
			SourceResourceID: "arn:aws:eks:us-east-1:123456789012:cluster/wave1-a",
			SourceARN:        "arn:aws:eks:us-east-1:123456789012:cluster/wave1-a",
			TargetResourceID: "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/WAVE1AAA",
			TargetARN:        "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/WAVE1AAA",
			TargetType:       "aws_eks_oidc_provider",
			Attributes:       map[string]any{"issuer_url": "https://oidc.eks.us-east-1.amazonaws.com/id/WAVE1AAA"},
			SourceRecordID:   "arn:aws:eks:us-east-1:123456789012:cluster/wave1-a#oidc-provider#arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/WAVE1AAA",
		},
		{
			Boundary:         Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "eks"},
			RelationshipType: "eks_cluster_has_nodegroup",
			SourceResourceID: "arn:aws:eks:us-east-1:123456789012:cluster/wave1-a",
			SourceARN:        "arn:aws:eks:us-east-1:123456789012:cluster/wave1-a",
			TargetResourceID: "arn:aws:eks:us-east-1:123456789012:nodegroup/wave1-a/ng-a1/11111111-2222-3333-4444-555555555555",
			TargetARN:        "arn:aws:eks:us-east-1:123456789012:nodegroup/wave1-a/ng-a1/11111111-2222-3333-4444-555555555555",
			TargetType:       "aws_eks_nodegroup",
			SourceRecordID:   "arn:aws:eks:us-east-1:123456789012:cluster/wave1-a#nodegroup#arn:aws:eks:us-east-1:123456789012:nodegroup/wave1-a/ng-a1/11111111-2222-3333-4444-555555555555",
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
		t.Fatalf("SDK rejected wave1 EKS result: %v", err)
	}
	report := conformance.Run(coreFixtureRequest(t, loadManifest(t), []sdk.Result{result}))
	if !report.OK() {
		t.Fatalf("wave1 EKS conformance findings = %#v, want passed", report.Findings)
	}
}
