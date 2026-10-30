// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	"github.com/eshu-hq/eshu-sdk/factschema"
)

// frozenResourcePolicyPermissionKey is the in-tree stable key for the Wave 0
// fixture statement (testdata/wave0-specialty-parity.json, resource_policy
// section), executed through the in-tree
// NewResourcePolicyPermissionEnvelope. Provenance for the frozen value is
// recorded on eshu-hq/eshu#9296 with the oracle run.
const frozenResourcePolicyPermissionKey = "6c5e4d83954ab445f141894167859aea185d9d46e930072f0912355aa4ba820c"

func resourcePolicyParityObservation(t *testing.T) ResourcePolicyPermissionObservation {
	t.Helper()
	in := loadWave0Fixture(t).ResourcePolicy
	return ResourcePolicyPermissionObservation{
		Boundary:            wave0Boundary(t, catalog.ServiceS3),
		ResourceARN:         in.ResourceARN,
		ResourceType:        in.ResourceType,
		StatementSID:        in.StatementSID,
		Effect:              in.Effect,
		Actions:             in.Actions,
		Resources:           in.Resources,
		ConditionKeys:       in.ConditionKeys,
		ConditionOperators:  in.ConditionOperators,
		PrincipalAccountIDs: in.PrincipalAccountIDs,
		PrincipalARNs:       in.PrincipalARNs,
		PrincipalTypes:      in.PrincipalTypes,
		IsPublic:            in.IsPublic,
		IsCrossAccount:      in.IsCrossAccount,
		SourceURI:           "aws:s3:bucket/parity-artifacts",
		SourceRecordID:      "resource-policy-row-1",
	}
}

func TestResourcePolicyPermissionFactWave0Parity(t *testing.T) {
	t.Parallel()

	fact, err := NewResourcePolicyPermissionFact(resourcePolicyParityObservation(t))
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindResourcePolicyPermission || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.StableKey != frozenResourcePolicyPermissionKey {
		t.Fatalf("StableKey = %q, want in-tree frozen %q", fact.StableKey, frozenResourcePolicyPermissionKey)
	}
	// The statement Sid feeds only the source-record id, never the payload.
	raw, err := json.Marshal(fact.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "AllowParityReads") {
		t.Fatal("payload contains statement Sid, want source-record id only")
	}
	if got, want := fact.SourceRef.RecordID, "resource-policy-row-1"; got != want {
		t.Fatalf("RecordID = %q, want %q", got, want)
	}
	decoded, err := factschema.DecodeAWSResourcePolicyPermission(factschema.Envelope{
		FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload,
	})
	if err != nil || decoded.PolicySource == nil || *decoded.PolicySource != "resource" {
		t.Fatalf("typed decode = %+v, %v", decoded, err)
	}
}

func TestResourcePolicyPermissionFactRejectsHostileInput(t *testing.T) {
	t.Parallel()

	observation := resourcePolicyParityObservation(t)
	observation.ResourceARN = ""
	if _, err := NewResourcePolicyPermissionFact(observation); err == nil {
		t.Fatal("blank resource_arn accepted")
	}
	observation = resourcePolicyParityObservation(t)
	observation.Effect = "maybe"
	if _, err := NewResourcePolicyPermissionFact(observation); err == nil {
		t.Fatal("non-Allow/Deny effect accepted")
	}
}
