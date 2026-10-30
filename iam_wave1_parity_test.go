// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	"github.com/eshu-hq/eshu-sdk/factschema"
)

// Wave 1 iam-resource parity pins (eshu-hq/eshu#9296, Q4 bar items (a)+(b)).
// Each frozen value below is the in-tree envelope output for the shared
// fixture role ("parity-runtime") and user ("parity-user"), executed through
// the in-tree iam scanner observation builders (roleObservation,
// userObservation, roleTrustRelationship, rolePolicyRelationship) plus
// NewResourceEnvelope / NewRelationshipEnvelope.
//
// Re-derivation recipe: eshu origin/main 0b1bb14203, throwaway package-iam
// probe TestZZWave1IAMOracle exercising those builders on the fixture model,
// `go test ./internal/collector/awscloud/service/iam/ -run TestZZWave1IAMOracle`
// from go/. Probe files deleted after the run; this test is the durable pin.
// Fixture boundary carries the production iam region: account 123456789012,
// region aws-global, scope "aws:123456789012:us-east-1", generation
// "aws:123456789012:us-east-1:parity:1", instance "aws-parity-8852".
const (
	frozenWave1IAMRoleKey      = "d9f27e386caa06c5591ddd597332a11bcdce7c4b5950bb3a563aef09cac35fc8"
	frozenWave1IAMTrust0Key    = "aea1a0181480ebf46a05c0595b3aa523ee1368b6edbb3974f176919a16d68080"
	frozenWave1IAMTrust1Key    = "61e5dac793ee3e1d568430f5d57f46740fbae8df86377b1e5b920148a21b2b3f"
	frozenWave1IAMPolicyRelKey = "6f04584135ff1b2ceb754bdabd7f2bc406b3297ec986fa3dff3ff94f715181eb"
	frozenWave1IAMUserKey      = "46dc193cf92e5d2a5d20cbeac04396e30b6d3b89aae9b7fdbc8f9a6281e74d56"
)

// frozenWave1IAMTrust0Payload is the in-tree canonical aws_relationship
// payload for the fixture role's first trust edge.
const frozenWave1IAMTrust0Payload = `{"account_id":"123456789012","attributes":{"principal_type":"AWS"},"collector_instance_id":"aws-parity-8852","region":"aws-global","relationship_type":"iam_role_trusts_principal","service_kind":"iam","source_arn":"arn:aws:iam::123456789012:role/parity-runtime","source_resource_id":"arn:aws:iam::123456789012:role/parity-runtime","target_arn":"","target_resource_id":"AWS:arn:aws:iam::123456789012:role/parity-trusted","target_type":"aws_iam_principal"}`

// frozenWave1IAMTrust1Payload is the in-tree canonical aws_relationship
// payload for the fixture role's second trust edge (Service,
// ec2.amazonaws.com). Key and payload corroborated independently: the key is
// the sha256 of the edge identity the envelope code hashes (see the probe
// note in the review thread), and the payload follows the Trust0 shape with
// only principal_type and target_resource_id changed.
const frozenWave1IAMTrust1Payload = `{"account_id":"123456789012","attributes":{"principal_type":"Service"},"collector_instance_id":"aws-parity-8852","region":"aws-global","relationship_type":"iam_role_trusts_principal","service_kind":"iam","source_arn":"arn:aws:iam::123456789012:role/parity-runtime","source_resource_id":"arn:aws:iam::123456789012:role/parity-runtime","target_arn":"","target_resource_id":"Service:ec2.amazonaws.com","target_type":"aws_iam_principal"}`

// frozenWave1IAMPolicyRelPayload is the in-tree canonical aws_relationship
// payload for the fixture role's attached-policy edge.
const frozenWave1IAMPolicyRelPayload = `{"account_id":"123456789012","attributes":null,"collector_instance_id":"aws-parity-8852","region":"aws-global","relationship_type":"iam_role_attached_policy","service_kind":"iam","source_arn":"arn:aws:iam::123456789012:role/parity-runtime","source_resource_id":"arn:aws:iam::123456789012:role/parity-runtime","target_arn":"arn:aws:iam::aws:policy/parity-managed","target_resource_id":"arn:aws:iam::aws:policy/parity-managed","target_type":"aws_iam_policy"}`

func wave1IAMBoundary(t *testing.T) Boundary {
	t.Helper()
	return Boundary{
		AccountID: "123456789012", Region: "aws-global", ServiceKind: catalog.ServiceIAM,
		ScopeID: "aws:123456789012:us-east-1", GenerationID: "aws:123456789012:us-east-1:parity:1",
		CollectorInstanceID: "aws-parity-8852", FencingToken: 7,
		ObservedAt: time.Date(2026, 10, 20, 13, 0, 0, 0, time.UTC),
	}
}

// wave1IAMRoleObservation mirrors the in-tree roleObservation output for the
// fixture role, including the trust-principal derivation.
func wave1IAMRoleObservation(t *testing.T) ResourceObservation {
	t.Helper()
	return ResourceObservation{
		Boundary:     wave1IAMBoundary(t),
		ARN:          "arn:aws:iam::123456789012:role/parity-runtime",
		ResourceID:   "arn:aws:iam::123456789012:role/parity-runtime",
		ResourceType: catalog.ResourceTypeIAMRole,
		Name:         "parity-runtime",
		Attributes: map[string]any{
			"attached_policy_arns":     []string{"arn:aws:iam::aws:policy/parity-managed"},
			"inline_policy_names":      []string{"parity-inline"},
			"path":                     "/parity/",
			"permission_boundary_arn":  "arn:aws:iam::123456789012:policy/parity-boundary",
			"permission_boundary_type": "PermissionsBoundary",
			"trust_policy_present":     true,
			"trust_principal_count":    2,
			"trust_principals": []map[string]string{
				{"type": "AWS", "identifier": "arn:aws:iam::123456789012:role/parity-trusted"},
				{"type": "Service", "identifier": "ec2.amazonaws.com"},
			},
		},
		CorrelationAnchors: []string{
			"arn:aws:iam::123456789012:role/parity-runtime",
			"parity-runtime",
		},
		SourceURI:      "aws:iam:role/parity-runtime",
		SourceRecordID: "arn:aws:iam::123456789012:role/parity-runtime",
	}
}

func wave1IAMUserObservation(t *testing.T) ResourceObservation {
	t.Helper()
	return ResourceObservation{
		Boundary:     wave1IAMBoundary(t),
		ARN:          "arn:aws:iam::123456789012:user/parity-user",
		ResourceID:   "arn:aws:iam::123456789012:user/parity-user",
		ResourceType: catalog.ResourceTypeIAMUser,
		Name:         "parity-user",
		Attributes: map[string]any{
			"attached_policy_arns":     []string{"arn:aws:iam::aws:policy/parity-managed"},
			"inline_policy_names":      []string{"parity-user-inline"},
			"path":                     "/parity/",
			"permission_boundary_arn":  "arn:aws:iam::123456789012:policy/parity-boundary",
			"permission_boundary_type": "PermissionsBoundary",
		},
		CorrelationAnchors: []string{
			"arn:aws:iam::123456789012:user/parity-user",
			"parity-user",
		},
		SourceURI:      "aws:iam:user/parity-user",
		SourceRecordID: "arn:aws:iam::123456789012:user/parity-user",
	}
}

func wave1IAMTrustObservation(t *testing.T, principalType, identifier string) RelationshipObservation {
	t.Helper()
	targetID := principalType + ":" + identifier
	return RelationshipObservation{
		Boundary:         wave1IAMBoundary(t),
		RelationshipType: catalog.RelationshipIAMRoleTrustsPrincipal,
		SourceResourceID: "arn:aws:iam::123456789012:role/parity-runtime",
		SourceARN:        "arn:aws:iam::123456789012:role/parity-runtime",
		TargetResourceID: targetID,
		TargetType:       catalog.ResourceTypeIAMPrincipal,
		Attributes:       map[string]any{"principal_type": principalType},
		SourceURI:        "aws:iam:role/parity-runtime",
		SourceRecordID:   "arn:aws:iam::123456789012:role/parity-runtime#trust#" + targetID,
	}
}

func wave1IAMPolicyObservation(t *testing.T) RelationshipObservation {
	t.Helper()
	return RelationshipObservation{
		Boundary:         wave1IAMBoundary(t),
		RelationshipType: catalog.RelationshipIAMRoleAttachedPolicy,
		SourceResourceID: "arn:aws:iam::123456789012:role/parity-runtime",
		SourceARN:        "arn:aws:iam::123456789012:role/parity-runtime",
		TargetResourceID: "arn:aws:iam::aws:policy/parity-managed",
		TargetARN:        "arn:aws:iam::aws:policy/parity-managed",
		TargetType:       catalog.ResourceTypeIAMPolicy,
		SourceURI:        "aws:iam:role/parity-runtime",
		SourceRecordID:   "arn:aws:iam::123456789012:role/parity-runtime#policy#arn:aws:iam::aws:policy/parity-managed",
	}
}

func checkWave1IAMResource(t *testing.T, observation ResourceObservation, frozenKey, resourceType string, attrKeys []string) {
	t.Helper()
	fact, err := NewResourceFact(observation)
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindResource || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.StableKey != frozenKey {
		t.Fatalf("StableKey = %q, want in-tree frozen %q", fact.StableKey, frozenKey)
	}
	if got := fact.Payload["resource_type"]; got != resourceType {
		t.Fatalf("resource_type = %#v, want %#v", got, resourceType)
	}
	if got := fact.Payload["region"]; got != "aws-global" {
		t.Fatalf("region = %#v, want aws-global", got)
	}
	attrs, ok := fact.Payload["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("payload attributes content = %#v", fact.Payload["attributes"])
	}
	for _, key := range attrKeys {
		if _, present := attrs[key]; !present {
			t.Fatalf("payload attributes miss %q", key)
		}
	}
	decoded, err := factschema.DecodeAWSResource(factschema.Envelope{
		FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload,
	})
	if err != nil || decoded.ResourceType != resourceType {
		t.Fatalf("typed decode = %+v, %v", decoded, err)
	}
}

func TestWave1IAMRoleResourceParity(t *testing.T) {
	t.Parallel()
	checkWave1IAMResource(t, wave1IAMRoleObservation(t), frozenWave1IAMRoleKey, catalog.ResourceTypeIAMRole,
		[]string{
			"attached_policy_arns", "inline_policy_names", "path",
			"permission_boundary_arn", "permission_boundary_type",
			"trust_policy_present", "trust_principal_count", "trust_principals",
		})
}

func TestWave1IAMUserResourceParity(t *testing.T) {
	t.Parallel()
	checkWave1IAMResource(t, wave1IAMUserObservation(t), frozenWave1IAMUserKey, catalog.ResourceTypeIAMUser,
		[]string{
			"attached_policy_arns", "inline_policy_names", "path",
			"permission_boundary_arn", "permission_boundary_type",
		})
}

func checkWave1IAMRelationship(t *testing.T, observation RelationshipObservation, frozenKey, frozenPayload, relationshipType string) {
	t.Helper()
	fact, err := NewRelationshipFact(observation)
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindRelationship || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.StableKey != frozenKey {
		t.Fatalf("StableKey = %q, want in-tree frozen %q", fact.StableKey, frozenKey)
	}
	raw, err := json.Marshal(fact.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != frozenPayload {
		t.Fatalf("payload = %s, want in-tree %s", raw, frozenPayload)
	}
	decoded, err := factschema.DecodeAWSRelationship(factschema.Envelope{
		FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload,
	})
	if err != nil || decoded.RelationshipType != relationshipType {
		t.Fatalf("typed decode = %+v, %v", decoded, err)
	}
}

func TestWave1IAMTrustRelationshipParity(t *testing.T) {
	t.Parallel()
	checkWave1IAMRelationship(t,
		wave1IAMTrustObservation(t, "AWS", "arn:aws:iam::123456789012:role/parity-trusted"),
		frozenWave1IAMTrust0Key, frozenWave1IAMTrust0Payload,
		catalog.RelationshipIAMRoleTrustsPrincipal)
}

func TestWave1IAMTrust1RelationshipParity(t *testing.T) {
	t.Parallel()
	checkWave1IAMRelationship(t,
		wave1IAMTrustObservation(t, "Service", "ec2.amazonaws.com"),
		frozenWave1IAMTrust1Key, frozenWave1IAMTrust1Payload,
		catalog.RelationshipIAMRoleTrustsPrincipal)
}

func TestWave1IAMPolicyRelationshipParity(t *testing.T) {
	t.Parallel()
	checkWave1IAMRelationship(t,
		wave1IAMPolicyObservation(t),
		frozenWave1IAMPolicyRelKey, frozenWave1IAMPolicyRelPayload,
		catalog.RelationshipIAMRoleAttachedPolicy)
}

func TestWave1IAMFactsRejectHostileInput(t *testing.T) {
	t.Parallel()

	observation := wave1IAMRoleObservation(t)
	observation.ARN = ""
	observation.ResourceID = "  "
	if _, err := NewResourceFact(observation); err == nil {
		t.Fatal("blank role identity accepted")
	}
	relationship := wave1IAMTrustObservation(t, "AWS", "arn:aws:iam::123456789012:role/parity-trusted")
	relationship.SourceResourceID = ""
	relationship.SourceARN = "  "
	if _, err := NewRelationshipFact(relationship); err == nil {
		t.Fatal("blank relationship source accepted")
	}
}
