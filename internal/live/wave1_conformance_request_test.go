// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"encoding/json"
	"os"
	"testing"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"
	"gopkg.in/yaml.v3"
)

// wave1CoreKinds is the Wave 0 emission contract the conformance harness
// authorizes against: the same twelve kinds the root coreFixtureRequest
// reserves (contract_manifest_test.go wave0CoreKinds, rebuilt here from the
// exported kind constants because test files cannot be imported).
var wave1CoreKinds = []string{
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

// wave1ConformanceRequest supplies synthetic authorization for live-package
// conformance runs. Production authorization comes only from the host's live
// grant snapshot. It mirrors the root coreFixtureRequest: local fixture mode,
// manifest from the repo root, per-kind schemas from the pinned fixture pack.
func wave1ConformanceRequest(t *testing.T, results []sdk.Result) conformance.Request {
	t.Helper()
	raw, err := os.ReadFile("../../manifest.yaml")
	if err != nil {
		t.Fatalf("os.ReadFile(manifest.yaml) error = %v", err)
	}
	var manifest conformance.Manifest
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("yaml.Unmarshal(manifest.yaml) error = %v", err)
	}
	request := conformance.Request{
		Manifest: manifest, Fixtures: results, Mode: conformance.ModeFixture,
		PayloadSchemas:    map[string]json.RawMessage{},
		ReservedFactKinds: append([]string(nil), wave1CoreKinds...),
		CoreFacts: &conformance.CoreFactContext{
			ComponentID: manifest.Metadata.ID, ComponentVersion: manifest.Metadata.Version,
		},
	}
	for _, kind := range wave1CoreKinds {
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
