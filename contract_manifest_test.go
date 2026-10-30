// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"
)

// Wave 0 acceptance: manifest.yaml and Contract() declare the same emitted
// fact families. The arbiter order (eshu-hq/eshu#9296, Wave 0 item 1) gates
// everything on reconciling the manifest against Contract(); this test locks
// the reconciliation so either side drifting reopens the gate.
//
// The twelve core-owned AWS kinds below are the Wave 0 emission contract:
// the four base kinds plus warning plus the eight specialty kinds seamed in
// this lane. aws_tag_observation stays out: it has no SDK encoder and no
// checked-in schema (schema-less registry-only kind), so Wave 2 decides
// between a seam and retirement-census first. The three transitional scaffold
// families ride alongside until the AWS logic port deletes them
// (PORT_PLAN.md).
var wave0CoreKinds = []string{
	AWSKindResource,
	AWSKindRelationship,
	AWSKindDNSRecord,
	AWSKindImageReference,
	AWSKindSecurityGroupRule,
	AWSKindIAMPermission,
	AWSKindResourcePolicyPermission,
	AWSKindWarning,
	AWSKindEC2InstancePosture,
	AWSKindS3BucketPosture,
	AWSKindRDSInstancePosture,
	AWSKindS3ExternalPrincipalGrant,
}

var wave0TransitionalKinds = []string{
	FactKindSnapshot,
	FactKindRecord,
	FactKindWarning,
}

func TestWave0ContractManifestParity(t *testing.T) {
	t.Parallel()

	contractVersions := make(map[string][]string, len(Contract().Facts))
	contractConfidence := make(map[string][]string, len(Contract().Facts))
	for _, decl := range Contract().Facts {
		if _, dup := contractVersions[decl.Kind]; dup {
			t.Fatalf("Contract() declares %q twice", decl.Kind)
		}
		contractVersions[decl.Kind] = decl.SchemaVersions
		confidence := make([]string, 0, len(decl.SourceConfidence))
		for _, c := range decl.SourceConfidence {
			confidence = append(confidence, string(c))
		}
		contractConfidence[decl.Kind] = confidence
	}

	manifest := loadManifest(t)
	manifestVersions := make(map[string][]string, len(manifest.Spec.EmittedFacts))
	manifestConfidence := make(map[string][]string, len(manifest.Spec.EmittedFacts))
	for _, family := range manifest.Spec.EmittedFacts {
		if _, dup := manifestVersions[family.Kind]; dup {
			t.Fatalf("manifest declares %q twice", family.Kind)
		}
		manifestVersions[family.Kind] = family.SchemaVersions
		manifestConfidence[family.Kind] = family.SourceConfidence
	}

	for _, kind := range append(append([]string(nil), wave0CoreKinds...), wave0TransitionalKinds...) {
		versions, ok := contractVersions[kind]
		if !ok {
			t.Errorf("Contract() does not declare %q", kind)
			continue
		}
		if len(versions) != 1 || versions[0] != "1.0.0" {
			t.Errorf("Contract() %q versions = %v, want [1.0.0]", kind, versions)
		}
		versions, ok = manifestVersions[kind]
		if !ok {
			t.Errorf("manifest does not declare %q", kind)
			continue
		}
		if len(versions) != 1 || versions[0] != "1.0.0" {
			t.Errorf("manifest %q versions = %v, want [1.0.0]", kind, versions)
		}
		if len(contractConfidence[kind]) != 1 || len(manifestConfidence[kind]) != 1 ||
			contractConfidence[kind][0] != manifestConfidence[kind][0] {
			t.Errorf("confidence mismatch for %q: contract=%v manifest=%v",
				kind, contractConfidence[kind], manifestConfidence[kind])
		}
	}
	if len(contractVersions) != len(wave0CoreKinds)+len(wave0TransitionalKinds) {
		t.Errorf("Contract() declares %d kinds, want %d (no unlisted families)",
			len(contractVersions), len(wave0CoreKinds)+len(wave0TransitionalKinds))
	}
	if len(manifestVersions) != len(wave0CoreKinds)+len(wave0TransitionalKinds) {
		t.Errorf("manifest declares %d kinds, want %d (no unlisted families)",
			len(manifestVersions), len(wave0CoreKinds)+len(wave0TransitionalKinds))
	}
}
