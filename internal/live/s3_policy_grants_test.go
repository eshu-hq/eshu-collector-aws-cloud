// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"
	"testing"
)

// lane0S3PolicyDocument is the shared oracle fixture policy: one public
// wildcard statement, one cross-account statement with a condition, one
// service-principal statement, one same-account statement (skipped for
// grants), and one Deny statement (no grant, still a statement). The
// in-tree awssdk derivation output for this document is the oracle
// (TestZZLane0S3Oracle, deleted after the run); this test freezes it.
const lane0S3PolicyDocument = `{"Version":"2012-10-17","Statement":[{"Sid":"PublicRead","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::parity-artifacts/*"},{"Sid":"CrossAccount","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999988887777:root"},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::parity-artifacts","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1234"}}},{"Sid":"ServiceDelivery","Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::parity-artifacts/*"},{"Sid":"SameAccount","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/app"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::parity-artifacts/*"},{"Sid":"DenyAll","Effect":"Deny","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"s3:*","Resource":"*"}]}`

func TestDeriveS3PolicyGrantsOracle(t *testing.T) {
	t.Parallel()

	grants, _, err := deriveS3PolicyFacts(lane0S3PolicyDocument, "arn:aws:s3:::parity-artifacts", "parity-artifacts", "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 3 {
		t.Fatalf("grants = %d, want 3 (same-account skipped, deny ignored)", len(grants))
	}
	for _, grant := range grants {
		if grant.SourceStatementID == "DenyAll" {
			t.Fatalf("deny statement emitted a grant: %+v", grant)
		}
	}
	first := grants[0]
	if first.PrincipalKind != "public" || first.PrincipalValue != "*" || first.GrantOutcome != "public" || !first.Public || first.SourceStatementID != "PublicRead" {
		t.Fatalf("grant[0] = %+v", first)
	}
	second := grants[1]
	if second.PrincipalKind != "aws_arn" || second.PrincipalAccountID != "999988887777" || second.PrincipalPartition != "aws" || !second.CrossAccount || second.SourceStatementID != "CrossAccount" {
		t.Fatalf("grant[1] = %+v", second)
	}
	third := grants[2]
	if third.PrincipalKind != "aws_service" || third.PrincipalService != "logging.s3.amazonaws.com" || !third.ServicePrincipal || third.SourceStatementID != "ServiceDelivery" {
		t.Fatalf("grant[2] = %+v", third)
	}
	for _, grant := range grants {
		if grant.BucketARN != "arn:aws:s3:::parity-artifacts" || grant.BucketName != "parity-artifacts" {
			t.Fatalf("grant bucket identity = %+v", grant)
		}
	}
}

func TestDeriveS3PolicyStatementsOracle(t *testing.T) {
	t.Parallel()

	_, statements, err := deriveS3PolicyFacts(lane0S3PolicyDocument, "arn:aws:s3:::parity-artifacts", "parity-artifacts", "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) != 5 {
		t.Fatalf("statements = %d, want 5", len(statements))
	}
	bySID := make(map[string]int, len(statements))
	for i, statement := range statements {
		bySID[statement.StatementSID] = i
		if statement.ResourceARN != "arn:aws:s3:::parity-artifacts" || statement.ResourceType != "aws_s3_bucket" {
			t.Fatalf("statement %q resource = %q %q", statement.StatementSID, statement.ResourceARN, statement.ResourceType)
		}
	}
	public := statements[bySID["PublicRead"]]
	if !public.IsPublic || public.Effect != "Allow" || len(public.Actions) != 1 || public.Actions[0] != "s3:GetObject" {
		t.Fatalf("PublicRead = %+v", public)
	}
	cross := statements[bySID["CrossAccount"]]
	if cross.IsPublic || !cross.IsCrossAccount || len(cross.PrincipalAccountIDs) != 1 || cross.PrincipalAccountIDs[0] != "999988887777" {
		t.Fatalf("CrossAccount = %+v", cross)
	}
	if len(cross.ConditionKeys) != 1 || cross.ConditionKeys[0] != "aws:SourceVpce" || len(cross.ConditionOperators) != 1 || cross.ConditionOperators[0] != "StringEquals" {
		t.Fatalf("CrossAccount conditions = %+v", cross)
	}
	same := statements[bySID["SameAccount"]]
	if same.IsPublic || same.IsCrossAccount || len(same.PrincipalARNs) != 1 {
		t.Fatalf("SameAccount = %+v", same)
	}
	deny := statements[bySID["DenyAll"]]
	if deny.Effect != "Deny" || deny.IsPublic {
		t.Fatalf("DenyAll = %+v", deny)
	}
}

func TestDeriveS3PolicyFactsRejectsRawDocument(t *testing.T) {
	t.Parallel()

	grants, statements, err := deriveS3PolicyFacts(lane0S3PolicyDocument, "arn:aws:s3:::parity-artifacts", "parity-artifacts", "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range grants {
		flat := grant.PrincipalKind + grant.PrincipalValue + grant.SourceStatementID
		if strings.Contains(flat, "2012-10-17") || strings.Contains(flat, "s3:GetObject") {
			t.Fatalf("grant retains policy text: %+v", grant)
		}
	}
	for _, statement := range statements {
		flat := strings.Join(statement.ConditionKeys, ",") + statement.StatementSID
		if strings.Contains(flat, "2012-10-17") || strings.Contains(flat, "vpce-1234") {
			t.Fatalf("statement retains condition values or document text: %+v", statement)
		}
	}
}

func TestDeriveS3PolicyFactsRejectsMalformed(t *testing.T) {
	t.Parallel()

	for _, document := range []string{"", "  ", "{not json"} {
		if _, _, err := deriveS3PolicyFacts(document, "arn:aws:s3:::parity-artifacts", "parity-artifacts", "123456789012"); err == nil {
			t.Fatalf("document %q accepted", document)
		}
	}
	// An empty statement list is a valid document with no derived facts,
	// mirroring the in-tree adapter.
	grants, statements, err := deriveS3PolicyFacts(`{"Statement":[]}`, "arn:aws:s3:::parity-artifacts", "parity-artifacts", "123456789012")
	if err != nil || len(grants) != 0 || len(statements) != 0 {
		t.Fatalf("empty statements = %d grants %d statements, err %v", len(grants), len(statements), err)
	}
}

func TestDeriveS3PolicyFactsSingleStatementShape(t *testing.T) {
	t.Parallel()

	document := `{"Version":"2012-10-17","Statement":{"Sid":"Solo","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}}`
	grants, statements, err := deriveS3PolicyFacts(document, "arn:aws:s3:::parity-artifacts", "parity-artifacts", "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || len(statements) != 1 || statements[0].StatementSID != "Solo" {
		t.Fatalf("grants=%d statements=%+v", len(grants), statements)
	}
}
