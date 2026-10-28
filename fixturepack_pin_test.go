// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"
)

// namespacedKind is this collector's namespaced fact kind validated against
// a pinned core payload shape. It exercises the payload-schema path without
// claiming a core-owned kind; the AWS logic port (PORT_PLAN.md) wires the
// real core-owned AWS kinds with their checked-in schemas.
const namespacedKind = "collector-aws-cloud.aws_resource"

// TestPinnedFixturePackPassesConformance proves this repo pins the
// fixture-pack version (the factschema module version) and validates payload
// shape against the exact schemas the target reducer release decodes: the
// pack's valid payload passes and its invalid payload fails closed.
func TestPinnedFixturePackPassesConformance(t *testing.T) {
	t.Parallel()

	schema, ok := fixturepack.SchemaFor("aws_resource")
	if !ok {
		t.Fatal("pinned fixture pack ships no schema for aws_resource")
	}
	schemas := map[string]json.RawMessage{namespacedKind: schema}

	validPayload, ok := fixturepack.ValidPayload("aws_resource")
	if !ok {
		t.Fatal("pinned fixture pack ships no valid payload for aws_resource")
	}
	if report := conformance.Run(pinnedRequest(t, validPayload, schemas)); !report.OK() {
		t.Fatalf("pinned valid payload: findings = %#v, want passed", report.Findings)
	}

	invalidPayload, ok := fixturepack.InvalidPayload("aws_resource")
	if !ok {
		t.Fatal("pinned fixture pack ships no invalid payload for aws_resource")
	}
	report := conformance.Run(pinnedRequest(t, invalidPayload, schemas))
	if report.OK() {
		t.Fatal("pinned invalid payload: report OK = true, want failed closed")
	}
	if !hasFinding(report, conformance.FindingPayloadSchemaInvalid) {
		t.Fatalf("pinned invalid payload: findings = %#v, want payload_schema_invalid", report.Findings)
	}
}

func pinnedRequest(t *testing.T, payload map[string]any, schemas map[string]json.RawMessage) conformance.Request {
	t.Helper()
	observedAt := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)
	manifest := loadManifest(t)
	manifest.Spec.EmittedFacts = append(manifest.Spec.EmittedFacts, conformance.FactFamily{
		Kind:             namespacedKind,
		SchemaVersions:   []string{"1.0.0"},
		SourceConfidence: []string{"observed"},
	})
	result := sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultComplete,
		Claim:           testClaim(),
		Generation:      sdk.Generation{ID: "generation-1", ObservedAt: observedAt},
		Facts: []sdk.Fact{{
			Kind:             namespacedKind,
			SchemaVersion:    "1.0.0",
			StableKey:        "aws-cloud:aws-resource:1",
			SourceConfidence: sdk.SourceConfidenceObserved,
			ObservedAt:       observedAt,
			SourceRef: sdk.SourceRef{
				SourceSystem: SourceSystem,
				ScopeID:      "component:aws-cloud-primary",
				GenerationID: "generation-1",
				FactKey:      "aws-cloud:aws-resource:1",
				URI:          "https://example.invalid/source/aws-cloud#aws-1",
				RecordID:     "aws-1",
			},
			Payload: payload,
		}},
	}
	return conformance.Request{Manifest: manifest, Fixtures: []sdk.Result{result}, Mode: conformance.ModeFixture, PayloadSchemas: schemas}
}

// TestTrustedCoreKindConformance checks the portable fixture path before the
// AWS scanner port. Only a host-supplied authorization context may admit a
// bare core kind; this synthetic context does not grant production authority.
func TestTrustedCoreKindConformance(t *testing.T) {
	t.Parallel()
	schema, ok := fixturepack.SchemaFor("aws_resource")
	if !ok {
		t.Fatal("pinned fixture pack ships no aws_resource schema")
	}
	payload, ok := fixturepack.ValidPayload("aws_resource")
	if !ok {
		t.Fatal("pinned fixture pack ships no aws_resource payload")
	}
	request := pinnedRequest(t, payload, map[string]json.RawMessage{"aws_resource": schema})
	request.Manifest.Spec.EmittedFacts[len(request.Manifest.Spec.EmittedFacts)-1] = conformance.FactFamily{
		Kind: "aws_resource", SchemaVersions: []string{"1.0.0"},
		SourceConfidence: []string{"reported"}, PayloadSchemaRef: "aws_resource",
	}
	request.Manifest.Spec.ConsumerContracts.Reducer.Phases = append(
		request.Manifest.Spec.ConsumerContracts.Reducer.Phases, "proof.synthetic:aws_resource")
	request.Fixtures[0].Facts[0].Kind = "aws_resource"
	request.Fixtures[0].Facts[0].SourceConfidence = sdk.SourceConfidenceReported
	request.ReservedFactKinds = []string{"aws_resource"}
	request.CoreFacts = &conformance.CoreFactContext{
		ComponentID:      request.Manifest.Metadata.ID,
		ComponentVersion: request.Manifest.Metadata.Version,
		Facts: []conformance.CoreFactAuthorization{{
			Kind: "aws_resource", PayloadSchemaRef: "aws_resource",
			ReducerPhases: []string{"proof.synthetic:aws_resource"},
			Emissions: []conformance.CoreFactEmission{{
				CollectorKind: CollectorKind, SchemaVersions: []string{"1.0.0"},
			}},
		}},
	}
	if report := conformance.Run(request); !report.OK() {
		t.Fatalf("trusted core fixture: findings = %#v", report.Findings)
	}
	request.CoreFacts = nil
	if report := conformance.Run(request); report.OK() ||
		!hasFinding(report, conformance.FindingManifestInvalid) {
		t.Fatalf("grantless core fixture: findings = %#v, want manifest_invalid", report.Findings)
	}
}
