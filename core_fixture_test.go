// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"
)

// coreFixtureRequest supplies synthetic authorization for local conformance.
// Production authorization comes only from the host's live grant snapshot.
func coreFixtureRequest(t *testing.T, manifest conformance.Manifest, fixtures []sdk.Result) conformance.Request {
	t.Helper()
	request := conformance.Request{
		Manifest: manifest, Fixtures: fixtures, Mode: conformance.ModeFixture,
		PayloadSchemas:    map[string]json.RawMessage{},
		ReservedFactKinds: []string{AWSKindResource, AWSKindRelationship, AWSKindImageReference, AWSKindWarning},
		CoreFacts: &conformance.CoreFactContext{
			ComponentID: manifest.Metadata.ID, ComponentVersion: manifest.Metadata.Version,
		},
	}
	for _, kind := range []string{AWSKindResource, AWSKindRelationship, AWSKindImageReference, AWSKindWarning} {
		schema, ok := fixturepack.SchemaFor(kind)
		if !ok {
			t.Fatalf("pinned fixture pack has no %s schema", kind)
		}
		request.PayloadSchemas[kind] = schema
		request.CoreFacts.Facts = append(request.CoreFacts.Facts, conformance.CoreFactAuthorization{
			Kind: kind, PayloadSchemaRef: kind,
			ReducerPhases: []string{"aws_cloud_runtime_drift"},
			Emissions:     []conformance.CoreFactEmission{{CollectorKind: CollectorKind, SchemaVersions: []string{"1.0.0"}}},
		})
	}
	return request
}
