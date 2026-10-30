// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

const wave1TrustDocument = `{"Version":"2012-10-17","Statement":[` +
	`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/parity-trusted"}},` +
	`{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com"]}}]}`

func wave1TrustRole() (listed iamtypes.Role, detail iamtypes.Role) {
	arn := "arn:aws:iam::123456789012:role/parity-runtime"
	listed = iamtypes.Role{Arn: aws.String(arn), RoleName: aws.String("parity-runtime"), Path: aws.String("/parity/")}
	detail = listed
	detail.AssumeRolePolicyDocument = aws.String(wave1TrustDocument)
	return listed, detail
}

func TestIAMRoleRecordDerivesTrustPrincipals(t *testing.T) {
	t.Parallel()

	listed, detail := wave1TrustRole()
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	row, err := iamRoleRecord(listed, &detail,
		[]string{"arn:aws:iam::aws:policy/parity-managed"}, []string{"parity-inline"},
		"us-east-1", identity)
	if err != nil {
		t.Fatal(err)
	}
	attrs := row.Resource.Attributes
	if attrs["trust_policy_present"] != true {
		t.Fatalf("trust_policy_present = %#v", attrs["trust_policy_present"])
	}
	if attrs["trust_principal_count"] != 2 {
		t.Fatalf("trust_principal_count = %#v", attrs["trust_principal_count"])
	}
	principals, ok := attrs["trust_principals"].([]map[string]string)
	if !ok || len(principals) != 2 ||
		principals[0]["type"] != "AWS" ||
		principals[0]["identifier"] != "arn:aws:iam::123456789012:role/parity-trusted" ||
		principals[1]["type"] != "Service" ||
		principals[1]["identifier"] != "ec2.amazonaws.com" {
		t.Fatalf("trust_principals = %#v", attrs["trust_principals"])
	}
	encoded, err := json.Marshal(attrs)
	if err != nil {
		t.Fatal(err)
	}
	// Derived principal identities are graph evidence by design; raw policy
	// syntax must never reach the attributes.
	for _, leaked := range []string{`"Statement"`, `"Principal"`, "Effect"} {
		if strings.Contains(string(encoded), leaked) {
			t.Fatalf("raw policy syntax leaked into attributes: %s", encoded)
		}
	}
}

func TestIAMRoleRecordsAttachTrustAndPolicyEdges(t *testing.T) {
	t.Parallel()

	listed, detail := wave1TrustRole()
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	client := &fakeIAMRoleAPI{listed: listed, detail: &detail}
	rows, err := listIAMRoleRecords(context.Background(), client, "us-east-1", identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	edges := rows[0].Relationships
	if len(edges) != 3 {
		t.Fatalf("relationships = %+v, want 2 trust + 1 policy edge", edges)
	}
	roleARN := "arn:aws:iam::123456789012:role/parity-runtime"
	var trust, policy int
	for _, edge := range edges {
		switch edge.RelationshipType {
		case catalog.RelationshipIAMRoleTrustsPrincipal:
			trust++
			if edge.SourceARN != roleARN || edge.Region != "aws-global" || edge.ServiceKind != catalog.ServiceIAM {
				t.Fatalf("trust edge = %+v", edge)
			}
		case catalog.RelationshipIAMRoleAttachedPolicy:
			policy++
			if edge.TargetARN != "arn:aws:iam::123456789012:policy/read" {
				t.Fatalf("policy edge = %+v", edge)
			}
		default:
			t.Fatalf("unexpected edge = %+v", edge)
		}
	}
	if trust != 2 || policy != 1 {
		t.Fatalf("trust=%d policy=%d, want 2 and 1", trust, policy)
	}
	if edges[0].SourceRecordID != roleARN+"#trust#AWS:arn:aws:iam::123456789012:role/parity-trusted" {
		t.Fatalf("trust record ID = %q", edges[0].SourceRecordID)
	}
}

func TestIAMTrustDerivationShapes(t *testing.T) {
	t.Parallel()

	// A statement without Principal contributes nothing; NotPrincipal is
	// ignored, mirroring the in-tree derivation.
	present, principals, err := parseIAMTrustPolicy(`{"Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"*"}}]}`)
	if err != nil || !present || len(principals) != 0 {
		t.Fatalf("not-principal = %v %v %v", present, principals, err)
	}
	// Bare-string and list principals normalize to AWS-typed entries.
	_, principals, err = parseIAMTrustPolicy(`{"Statement":[{"Effect":"Allow","Principal":"*"}]}`)
	if err != nil || len(principals) != 1 || principals[0].Type != "AWS" || principals[0].Identifier != "*" {
		t.Fatalf("bare principal = %v %v", principals, err)
	}
	// URL-encoded documents decode before parsing.
	_, principals, err = parseIAMTrustPolicy(`%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22ec2.amazonaws.com%22%7D%7D%5D%7D`)
	if err != nil || len(principals) != 1 || principals[0].Identifier != "ec2.amazonaws.com" {
		t.Fatalf("encoded principal = %v %v", principals, err)
	}
	if _, _, err = parseIAMTrustPolicy("not-json{"); err == nil || strings.Contains(err.Error(), "not-json") {
		t.Fatalf("malformed trust must fail without raw value: %v", err)
	}
}

func TestIAMTrustMultiKeyPrincipalOrderIsDeterministic(t *testing.T) {
	t.Parallel()

	// One statement carrying two principal keys must not depend on Go map
	// iteration order: trust_principals attribute order and trust-edge
	// emission order feed frozen payloads.
	document := `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com","AWS":"arn:aws:iam::123456789012:role/parity-trusted"}}]}`
	for range 50 {
		_, principals, err := parseIAMTrustPolicy(document)
		if err != nil {
			t.Fatal(err)
		}
		if len(principals) != 2 ||
			principals[0].Type != "AWS" ||
			principals[0].Identifier != "arn:aws:iam::123456789012:role/parity-trusted" ||
			principals[1].Type != "Service" ||
			principals[1].Identifier != "ec2.amazonaws.com" {
			t.Fatalf("multi-key principals = %+v, want AWS before Service", principals)
		}
	}
}

// Frozen wave-1 pins duplicated from iam_wave1_parity_test.go: root-package
// test files are not importable, so the live chain test carries its own copy.
// If the root pins move, this test fails loudly by design — two witnesses,
// one truth.
const (
	chainWave1IAMRoleKey      = "d9f27e386caa06c5591ddd597332a11bcdce7c4b5950bb3a563aef09cac35fc8"
	chainWave1IAMTrust0Key    = "aea1a0181480ebf46a05c0595b3aa523ee1368b6edbb3974f176919a16d68080"
	chainWave1IAMTrust1Key    = "61e5dac793ee3e1d568430f5d57f46740fbae8df86377b1e5b920148a21b2b3f"
	chainWave1IAMPolicyRelKey = "6f04584135ff1b2ceb754bdabd7f2bc406b3297ec986fa3dff3ff94f715181eb"
)

const (
	chainWave1IAMTrust0Payload    = `{"account_id":"123456789012","attributes":{"principal_type":"AWS"},"collector_instance_id":"aws-parity-8852","region":"aws-global","relationship_type":"iam_role_trusts_principal","service_kind":"iam","source_arn":"arn:aws:iam::123456789012:role/parity-runtime","source_resource_id":"arn:aws:iam::123456789012:role/parity-runtime","target_arn":"","target_resource_id":"AWS:arn:aws:iam::123456789012:role/parity-trusted","target_type":"aws_iam_principal"}`
	chainWave1IAMTrust1Payload    = `{"account_id":"123456789012","attributes":{"principal_type":"Service"},"collector_instance_id":"aws-parity-8852","region":"aws-global","relationship_type":"iam_role_trusts_principal","service_kind":"iam","source_arn":"arn:aws:iam::123456789012:role/parity-runtime","source_resource_id":"arn:aws:iam::123456789012:role/parity-runtime","target_arn":"","target_resource_id":"Service:ec2.amazonaws.com","target_type":"aws_iam_principal"}`
	chainWave1IAMPolicyRelPayload = `{"account_id":"123456789012","attributes":null,"collector_instance_id":"aws-parity-8852","region":"aws-global","relationship_type":"iam_role_attached_policy","service_kind":"iam","source_arn":"arn:aws:iam::123456789012:role/parity-runtime","source_resource_id":"arn:aws:iam::123456789012:role/parity-runtime","target_arn":"arn:aws:iam::aws:policy/parity-managed","target_resource_id":"arn:aws:iam::aws:policy/parity-managed","target_type":"aws_iam_policy"}`
	chainWave1IAMTrustPrincipals  = `[{"identifier":"arn:aws:iam::123456789012:role/parity-trusted","type":"AWS"},{"identifier":"ec2.amazonaws.com","type":"Service"}]`
)

// TestIAMRoleRecordMatchesFrozenEnvelope chains the production live path end
// to end: the fixture trust document through iamRoleRecord, the shipped
// collect-path mapping (resourceObservation/relationshipObservation), and the
// shipped claim stamping (AppendLiveResources/AppendLiveRelationships), then
// compares every emitted fact against the frozen in-tree pins. A swap of the
// two trust-principal values fails here: the resource attributes JSON moves
// and both trust-edge keys change identity.
func TestIAMRoleRecordMatchesFrozenEnvelope(t *testing.T) {
	t.Parallel()

	arn := "arn:aws:iam::123456789012:role/parity-runtime"
	listed := iamtypes.Role{Arn: aws.String(arn), RoleName: aws.String("parity-runtime"), Path: aws.String("/parity/")}
	detail := listed
	detail.AssumeRolePolicyDocument = aws.String(wave1TrustDocument)
	detail.PermissionsBoundary = &iamtypes.AttachedPermissionsBoundary{
		PermissionsBoundaryArn:  aws.String("arn:aws:iam::123456789012:policy/parity-boundary"),
		PermissionsBoundaryType: iamtypes.PermissionsBoundaryAttachmentType("PermissionsBoundary"),
	}
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	row, err := iamRoleRecord(listed, &detail,
		[]string{"arn:aws:iam::aws:policy/parity-managed"}, []string{"parity-inline"},
		"us-east-1", identity)
	if err != nil {
		t.Fatal(err)
	}

	resources := []collector.ResourceObservation{resourceObservation(identity.AccountID, row.Resource)}
	relationships := make([]collector.RelationshipObservation, 0, len(row.Relationships))
	for _, edge := range row.Relationships {
		relationships = append(relationships, relationshipObservation(identity.AccountID, edge))
	}
	base := sdk.Result{
		State: sdk.ResultComplete,
		Claim: sdk.Claim{
			Scope:        sdk.Scope{ID: "aws:123456789012:us-east-1"},
			GenerationID: "aws:123456789012:us-east-1:parity:1",
			InstanceID:   "aws-parity-8852",
			FencingToken: "fence-parity",
		},
		Generation: sdk.Generation{ObservedAt: time.Date(2026, 10, 20, 13, 0, 0, 0, time.UTC)},
	}
	stamped, err := collector.AppendLiveResources(base, resources, "aws:iam:role/parity-runtime", collector.ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	stamped, err = collector.AppendLiveRelationships(stamped, relationships, "aws:iam:role/parity-runtime", collector.ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stamped.Facts) != 4 {
		t.Fatalf("facts = %d, want 1 role + 2 trust + 1 policy", len(stamped.Facts))
	}
	byKey := make(map[string]sdk.Fact, len(stamped.Facts))
	for _, fact := range stamped.Facts {
		byKey[fact.Kind+"\x00"+fact.StableKey] = fact
	}
	role, ok := byKey[collector.AWSKindResource+"\x00"+chainWave1IAMRoleKey]
	if !ok {
		t.Fatalf("role fact with frozen key %q missing", chainWave1IAMRoleKey)
	}
	attrs, ok := role.Payload["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("role payload attributes = %#v", role.Payload["attributes"])
	}
	encoded, err := json.Marshal(attrs["trust_principals"])
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != chainWave1IAMTrustPrincipals {
		t.Fatalf("trust_principals = %s, want %s", encoded, chainWave1IAMTrustPrincipals)
	}
	for key, payload := range map[string]string{
		chainWave1IAMTrust0Key:    chainWave1IAMTrust0Payload,
		chainWave1IAMTrust1Key:    chainWave1IAMTrust1Payload,
		chainWave1IAMPolicyRelKey: chainWave1IAMPolicyRelPayload,
	} {
		fact, ok := byKey[collector.AWSKindRelationship+"\x00"+key]
		if !ok {
			t.Fatalf("relationship fact with frozen key %q missing", key)
		}
		raw, err := json.Marshal(fact.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != payload {
			t.Fatalf("payload = %s, want in-tree %s", raw, payload)
		}
	}
}

func TestIAMRoleWithoutTrustHasZeroCount(t *testing.T) {
	t.Parallel()

	arn := "arn:aws:iam::123456789012:role/demo"
	listed := iamtypes.Role{Arn: aws.String(arn), RoleName: aws.String("demo")}
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	row, err := iamRoleRecord(listed, nil, nil, nil, "us-east-1", identity)
	if err != nil {
		t.Fatal(err)
	}
	if row.Resource.Attributes["trust_principal_count"] != 0 {
		t.Fatalf("trust_principal_count = %#v", row.Resource.Attributes["trust_principal_count"])
	}
	if principals, ok := row.Resource.Attributes["trust_principals"].([]map[string]string); !ok || len(principals) != 0 {
		t.Fatalf("trust_principals = %#v", row.Resource.Attributes["trust_principals"])
	}
	if len(row.Relationships) != 0 {
		t.Fatalf("relationships = %+v, want none", row.Relationships)
	}
}
