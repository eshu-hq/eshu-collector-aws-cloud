// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
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
