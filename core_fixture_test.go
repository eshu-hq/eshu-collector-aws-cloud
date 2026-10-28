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
	schema, ok := fixturepack.SchemaFor(AWSKindResource)
	if !ok {
		t.Fatal("pinned fixture pack has no aws_resource schema")
	}
	return conformance.Request{
		Manifest: manifest, Fixtures: fixtures, Mode: conformance.ModeFixture,
		PayloadSchemas:    map[string]json.RawMessage{AWSKindResource: schema},
		ReservedFactKinds: []string{AWSKindResource},
		CoreFacts: &conformance.CoreFactContext{
			ComponentID: manifest.Metadata.ID, ComponentVersion: manifest.Metadata.Version,
			Facts: []conformance.CoreFactAuthorization{{
				Kind: AWSKindResource, PayloadSchemaRef: AWSKindResource,
				ReducerPhases: []string{"aws_cloud_runtime_drift"},
				Emissions: []conformance.CoreFactEmission{{
					CollectorKind: CollectorKind, SchemaVersions: []string{"1.0.0"},
				}},
			}},
		},
	}
}
