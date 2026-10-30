// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	"github.com/eshu-hq/eshu-sdk/factschema"
)

// frozenS3ExternalPrincipalGrantKey is the in-tree stable key for the Wave 0
// fixture grant (testdata/wave0-specialty-parity.json, s3_grant section),
// executed through the in-tree NewS3ExternalPrincipalGrantEnvelope.
// Re-derivation recipe (oracle commit, builder, fixture hash):
// testdata/stable-key-provenance.md.
const frozenS3ExternalPrincipalGrantKey = "57587047141fa905775f6adc563cd54d35cd4df4a8e74dada0cacfa8417fc3eb"

func s3GrantParityObservation(t *testing.T) S3ExternalPrincipalGrantObservation {
	t.Helper()
	in := loadWave0Fixture(t).S3Grant
	return S3ExternalPrincipalGrantObservation{
		Boundary:           wave0Boundary(t, catalog.ServiceS3),
		BucketARN:          in.BucketARN,
		BucketName:         in.BucketName,
		PrincipalKind:      in.PrincipalKind,
		PrincipalValue:     in.PrincipalValue,
		PrincipalAccountID: in.PrincipalAccountID,
		PrincipalPartition: in.PrincipalPartition,
		GrantOutcome:       in.GrantOutcome,
		Public:             in.Public,
		CrossAccount:       in.CrossAccount,
		ServicePrincipal:   in.ServicePrincipal,
		Unsupported:        in.Unsupported,
		SourceStatementID:  in.SourceStatementID,
		SourceURI:          "aws:s3:bucket/parity-artifacts",
		SourceRecordID:     "s3-grant-row-1",
	}
}

func TestS3ExternalPrincipalGrantFactWave0Parity(t *testing.T) {
	t.Parallel()

	fact, err := NewS3ExternalPrincipalGrantFact(s3GrantParityObservation(t))
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindS3ExternalPrincipalGrant || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.StableKey != frozenS3ExternalPrincipalGrantKey {
		t.Fatalf("StableKey = %q, want in-tree frozen %q", fact.StableKey, frozenS3ExternalPrincipalGrantKey)
	}
	// The cross_account outcome derives is_cross_account even though the
	// fixture's explicit CrossAccount flag is already true; both paths agree.
	if got, want := fact.Payload["is_cross_account"], true; got != want {
		t.Fatalf("is_cross_account = %#v, want %#v", got, want)
	}
	if got, want := fact.Payload["is_public"], false; got != want {
		t.Fatalf("is_public = %#v, want %#v", got, want)
	}
	decoded, err := factschema.DecodeS3ExternalPrincipalGrant(factschema.Envelope{
		FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload,
	})
	if err != nil || decoded.GrantOutcome != "cross_account" {
		t.Fatalf("typed decode = %+v, %v", decoded, err)
	}
}

func TestS3ExternalPrincipalGrantFactRejectsHostileInput(t *testing.T) {
	t.Parallel()

	observation := s3GrantParityObservation(t)
	observation.BucketARN = ""
	observation.BucketName = "  "
	if _, err := NewS3ExternalPrincipalGrantFact(observation); err == nil {
		t.Fatal("blank bucket identity accepted")
	}
	observation = s3GrantParityObservation(t)
	observation.PrincipalKind = ""
	if _, err := NewS3ExternalPrincipalGrantFact(observation); err == nil {
		t.Fatal("blank principal_kind accepted")
	}
	observation = s3GrantParityObservation(t)
	observation.GrantOutcome = ""
	if _, err := NewS3ExternalPrincipalGrantFact(observation); err == nil {
		t.Fatal("blank grant_outcome accepted")
	}
}
