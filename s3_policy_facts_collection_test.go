// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func lane0GrantObservation() S3ExternalPrincipalGrantObservation {
	return S3ExternalPrincipalGrantObservation{
		Boundary:          Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: catalog.ServiceS3},
		BucketARN:         "arn:aws:s3:::parity-artifacts",
		BucketName:        "parity-artifacts",
		PrincipalKind:     S3ExternalPrincipalKindPublic,
		PrincipalValue:    "*",
		GrantOutcome:      S3ExternalPrincipalGrantOutcomePublic,
		Public:            true,
		SourceStatementID: "LivePublic",
		SourceURI:         "aws:s3:bucket/parity-artifacts",
		SourceRecordID:    "s3-grant-row-1",
	}
}

func TestAppendLiveS3GrantsBindsClaim(t *testing.T) {
	t.Parallel()

	claim := testClaim()
	base := mustCollect(t, "complete.json", claim, testObservedAt(), "")
	observation := lane0GrantObservation()
	observation.Boundary.ScopeID = ""
	got, err := AppendLiveS3ExternalPrincipalGrants(base, []S3ExternalPrincipalGrantObservation{observation, observation}, "aws://123456789012", ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Facts) != len(base.Facts)+1 {
		t.Fatalf("facts = %d, want dedupe to one grant", len(got.Facts))
	}
	fact := got.Facts[len(got.Facts)-1]
	if fact.Kind != AWSKindS3ExternalPrincipalGrant || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if got := fact.Payload["principal_value"]; got != "*" {
		t.Fatalf("principal_value = %#v", got)
	}
	if fact.SourceRef.ScopeID != claim.Scope.ID || fact.SourceRef.GenerationID != claim.GenerationID {
		t.Fatalf("grant is not bound to claim: %#v", fact.SourceRef)
	}
}

func TestAppendLiveS3GrantsBoundsAndInvalidIdentity(t *testing.T) {
	t.Parallel()

	claim := testClaim()
	base := mustCollect(t, "complete.json", claim, testObservedAt(), "")
	bounded, err := AppendLiveS3ExternalPrincipalGrants(base, []S3ExternalPrincipalGrantObservation{lane0GrantObservation()}, "aws://123456789012", ResourceUse{MaxRecordsPerClaim: len(base.Facts), MaxPayloadBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	if bounded.State != sdk.ResultTerminal && len(bounded.Facts) != len(base.Facts) {
		t.Fatalf("unbounded grant emission: facts=%d state=%q", len(bounded.Facts), bounded.State)
	}
	observation := lane0GrantObservation()
	observation.BucketARN = ""
	observation.BucketName = "  "
	if _, err := AppendLiveS3ExternalPrincipalGrants(base, []S3ExternalPrincipalGrantObservation{observation}, "aws://123456789012", ResourceUse{}); err == nil {
		t.Fatal("blank grant bucket identity accepted")
	}
	observation = lane0GrantObservation()
	observation.PrincipalValue = "  "
	if _, err := AppendLiveS3ExternalPrincipalGrants(base, []S3ExternalPrincipalGrantObservation{observation}, "aws://123456789012", ResourceUse{}); err == nil {
		t.Fatal("blank grant principal accepted")
	}
}

func lane0StatementObservation() ResourcePolicyPermissionObservation {
	return ResourcePolicyPermissionObservation{
		Boundary:       Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: catalog.ServiceS3},
		ResourceARN:    "arn:aws:s3:::parity-artifacts",
		ResourceType:   catalog.ResourceTypeS3Bucket,
		StatementSID:   "LivePublic",
		Effect:         "Allow",
		Actions:        []string{"s3:GetObject"},
		Resources:      []string{"arn:aws:s3:::parity-artifacts/*"},
		PrincipalTypes: []string{"aws"},
		IsPublic:       true,
		SourceURI:      "aws:s3:bucket/parity-artifacts",
		SourceRecordID: "statement-row-1",
	}
}

func TestAppendLiveResourcePolicyPermissionsBindsClaim(t *testing.T) {
	t.Parallel()

	claim := testClaim()
	base := mustCollect(t, "complete.json", claim, testObservedAt(), "")
	observation := lane0StatementObservation()
	observation.Boundary.ScopeID = ""
	got, err := AppendLiveResourcePolicyPermissions(base, []ResourcePolicyPermissionObservation{observation, observation}, "aws://123456789012", ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Facts) != len(base.Facts)+1 {
		t.Fatalf("facts = %d, want dedupe to one statement", len(got.Facts))
	}
	fact := got.Facts[len(got.Facts)-1]
	if fact.Kind != AWSKindResourcePolicyPermission || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.SourceRef.ScopeID != claim.Scope.ID || fact.SourceRef.GenerationID != claim.GenerationID {
		t.Fatalf("statement is not bound to claim: %#v", fact.SourceRef)
	}
}

func TestAppendLiveResourcePolicyPermissionsBoundsAndInvalidIdentity(t *testing.T) {
	t.Parallel()

	claim := testClaim()
	base := mustCollect(t, "complete.json", claim, testObservedAt(), "")
	bounded, err := AppendLiveResourcePolicyPermissions(base, []ResourcePolicyPermissionObservation{lane0StatementObservation()}, "aws://123456789012", ResourceUse{MaxRecordsPerClaim: len(base.Facts), MaxPayloadBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	if bounded.State != sdk.ResultTerminal && len(bounded.Facts) != len(base.Facts) {
		t.Fatalf("unbounded statement emission: facts=%d state=%q", len(bounded.Facts), bounded.State)
	}
	observation := lane0StatementObservation()
	observation.ResourceARN = "  "
	if _, err := AppendLiveResourcePolicyPermissions(base, []ResourcePolicyPermissionObservation{observation}, "aws://123456789012", ResourceUse{}); err == nil {
		t.Fatal("blank statement resource accepted")
	}
	observation = lane0StatementObservation()
	observation.Effect = "grant"
	if _, err := AppendLiveResourcePolicyPermissions(base, []ResourcePolicyPermissionObservation{observation}, "aws://123456789012", ResourceUse{}); err == nil {
		t.Fatal("bad statement effect accepted")
	}
}
