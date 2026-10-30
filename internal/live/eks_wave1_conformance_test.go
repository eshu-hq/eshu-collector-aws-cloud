// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"
	"gopkg.in/yaml.v3"
)

// TestWave1EKSLiveConformance is the Wave 1 EKS Q4(a) gate over real builder
// output: every fact the production listEKS path emits for the shared fixture
// (all four resource kinds, all nine relationship kinds) validates against
// its checked-in JSON Schema through the public fixture harness. The
// companion parity test proves the same facts carry in-tree-identical stable
// keys (Q4(b)).
func TestWave1EKSLiveConformance(t *testing.T) {
	t.Parallel()

	fixture := loadWave1EKSFixture(t)
	cfg := wave1EKSStubConfig(t, fixture)
	records, err := listEKS(context.Background(), cfg, VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}

	const accountID = "123456789012"
	observedAt := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	result := sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultComplete,
		Claim: sdk.Claim{
			ComponentID: collector.ComponentID, InstanceID: "aws-parity-wave1",
			CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem,
			Scope:        sdk.Scope{ID: "aws:123456789012:us-east-1", Kind: "component"},
			GenerationID: "aws:123456789012:us-east-1:wave1:1",
			FencingToken: "wave1-parity-token",
			SourceRunID:  "run-wave1", WorkItemID: "work-wave1",
			Attempt: 1, Deadline: observedAt.Add(time.Hour), ConfigHandle: "component-config:aws-cloud",
		},
		Generation: sdk.Generation{ID: "aws:123456789012:us-east-1:wave1:1", ObservedAt: observedAt},
	}
	resourceTypes := map[string]bool{}
	relationshipTypes := map[string]bool{}
	for _, item := range records {
		if edge := item.Relationship; edge != nil {
			relationshipTypes[edge.RelationshipType] = true
			fact, err := collector.NewRelationshipFact(eksWave1Relationship(accountID, *edge))
			if err != nil {
				t.Fatal(err)
			}
			result.Facts = append(result.Facts, fact)
		}
		for _, edge := range item.Relationships {
			relationshipTypes[edge.RelationshipType] = true
			fact, err := collector.NewRelationshipFact(eksWave1Relationship(accountID, edge))
			if err != nil {
				t.Fatal(err)
			}
			result.Facts = append(result.Facts, fact)
		}
		if item.Resource == nil {
			continue
		}
		resourceTypes[item.Resource.ResourceType] = true
		fact, err := collector.NewResourceFact(eksWave1Resource(accountID, item.Resource))
		if err != nil {
			t.Fatal(err)
		}
		result.Facts = append(result.Facts, fact)
	}
	if len(result.Facts) != 24 {
		t.Fatalf("live facts = %d, want 24", len(result.Facts))
	}
	if len(resourceTypes) != 4 || len(relationshipTypes) != 9 {
		t.Fatalf("live types = %d resources %d relationships, want 4+9", len(resourceTypes), len(relationshipTypes))
	}
	if _, err := sdk.NewValidator(collector.Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected live EKS result: %v", err)
	}
	report := conformance.Run(wave1LiveConformanceRequest(t, []sdk.Result{result}))
	if !report.OK() {
		t.Fatalf("live EKS conformance findings = %#v, want passed", report.Findings)
	}
}

// wave1LiveConformanceRequest supplies synthetic authorization for
// live-package conformance runs. Production authorization comes only from the
// host's live grant snapshot. It mirrors the root coreFixtureRequest: local
// fixture mode, manifest from the repo root, per-kind schemas from the pinned
// fixture pack.
func wave1LiveConformanceRequest(t *testing.T, results []sdk.Result) conformance.Request {
	t.Helper()
	raw, err := os.ReadFile("../../manifest.yaml")
	if err != nil {
		t.Fatalf("os.ReadFile(manifest.yaml) error = %v", err)
	}
	var manifest conformance.Manifest
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("yaml.Unmarshal(manifest.yaml) error = %v", err)
	}
	kinds := []string{
		collector.AWSKindResource,
		collector.AWSKindRelationship,
		collector.AWSKindDNSRecord,
		collector.AWSKindImageReference,
		collector.AWSKindSecurityGroupRule,
		collector.AWSKindIAMPermission,
		collector.AWSKindResourcePolicyPermission,
		collector.AWSKindWarning,
		collector.AWSKindEC2InstancePosture,
		collector.AWSKindS3BucketPosture,
		collector.AWSKindRDSInstancePosture,
		collector.AWSKindS3ExternalPrincipalGrant,
	}
	request := conformance.Request{
		Manifest: manifest, Fixtures: results, Mode: conformance.ModeFixture,
		PayloadSchemas:    map[string]json.RawMessage{},
		ReservedFactKinds: append([]string(nil), kinds...),
		CoreFacts: &conformance.CoreFactContext{
			ComponentID: manifest.Metadata.ID, ComponentVersion: manifest.Metadata.Version,
		},
	}
	for _, kind := range kinds {
		schema, ok := fixturepack.SchemaFor(kind)
		if !ok {
			t.Fatalf("pinned fixture pack has no %s schema", kind)
		}
		request.PayloadSchemas[kind] = schema
		request.CoreFacts.Facts = append(request.CoreFacts.Facts, conformance.CoreFactAuthorization{
			Kind: kind, PayloadSchemaRef: kind,
			ReducerPhases: []string{"aws_cloud_runtime_drift"},
			Emissions:     []conformance.CoreFactEmission{{CollectorKind: collector.CollectorKind, SchemaVersions: []string{"1.0.0"}}},
		})
	}
	return request
}
