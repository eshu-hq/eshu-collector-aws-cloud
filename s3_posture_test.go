// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func TestS3PostureFactContainsOnlyReportedReplication(t *testing.T) {
	enabled := true
	fact, err := NewS3BucketPostureFact(S3BucketPostureObservation{
		Boundary:  Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "s3", ScopeID: "scope", GenerationID: "generation", CollectorInstanceID: "instance", ClaimToken: "fence", ObservedAt: time.Now()},
		BucketARN: "arn:aws:s3:::assets", BucketName: "assets", ReplicationEnabled: &enabled,
		SourceURI: "aws:source", SourceRecordID: "arn:aws:s3:::assets#posture",
	})
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindS3BucketPosture || fact.Payload["replication_enabled"] != true || fact.Payload["bucket_name"] != "assets" {
		t.Fatalf("fact = %+v", fact)
	}
	for _, field := range []string{"default_encryption_enabled", "block_public_acls", "policy_present", "logging_target_bucket"} {
		if _, present := fact.Payload[field]; present {
			t.Fatalf("unobserved %s emitted: %v", field, fact.Payload)
		}
	}
	if _, err := NewS3BucketPostureFact(S3BucketPostureObservation{
		Boundary:  Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "s3", ScopeID: "scope", GenerationID: "generation", CollectorInstanceID: "instance", ClaimToken: "fence"},
		BucketARN: "arn:aws:s3:::other", BucketName: "assets", SourceURI: "aws:source",
	}); err == nil {
		t.Fatal("mismatched bucket identity accepted")
	}
}

func TestAppendLiveS3PostureBindsClaimAndValidates(t *testing.T) {
	base := mustCollect(t, "complete.json", testClaim(), testObservedAt(), "")
	enabled := true
	observation := S3BucketPostureObservation{
		Boundary:  Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "s3"},
		BucketARN: "arn:aws:s3:::assets", BucketName: "assets", ReplicationEnabled: &enabled,
	}
	result, err := AppendLiveS3BucketPostures(base, []S3BucketPostureObservation{observation, observation}, "aws://123456789012", ResourceUse{})
	if err != nil || len(result.Facts) != len(base.Facts)+1 {
		t.Fatalf("append: facts=%d err=%v", len(result.Facts), err)
	}
	fact := result.Facts[len(result.Facts)-1]
	if fact.SourceRef.RecordID != "arn:aws:s3:::assets#posture" || fact.SourceRef.FactKey != fact.StableKey {
		t.Fatalf("source reference = %+v", fact.SourceRef)
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected typed posture: %v", err)
	}
	bounded, err := AppendLiveS3BucketPostures(base, []S3BucketPostureObservation{observation}, "aws://123456789012", ResourceUse{MaxRecordsPerClaim: len(base.Facts), MaxPayloadBytes: 65536})
	if err != nil || bounded.State != sdk.ResultTerminal {
		t.Fatalf("budget: state=%s err=%v", bounded.State, err)
	}
}

func TestS3PostureFactEncodesConfirmedFields(t *testing.T) {
	trueValue, falseValue := true, false
	status := "Enabled"
	fact, err := NewS3BucketPostureFact(S3BucketPostureObservation{
		Boundary:  Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "s3", ScopeID: "scope", GenerationID: "generation", CollectorInstanceID: "instance", ClaimToken: "fence"},
		BucketARN: "arn:aws:s3:::assets", BucketName: "assets", SourceURI: "aws:source",
		LoggingEnabled: &trueValue, LoggingTargetBucket: "audit",
		VersioningStatus: &status, VersioningEnabled: &trueValue, MFADeleteEnabled: &falseValue,
		ObjectOwnership: []string{"BucketOwnerEnforced"}, ACLDisabled: &trueValue,
		DefaultEncryptionEnabled: &trueValue, EncryptionAlgorithms: []string{"aws:kms"},
		SSEKMSKeyARN: "alias/team", BucketKeyEnabled: &trueValue,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fact.Payload["logging_enabled"] != true || fact.Payload["logging_target_bucket"] != "audit" || fact.Payload["versioning_status"] != "Enabled" || fact.Payload["mfa_delete_enabled"] != false || fact.Payload["acl_disabled"] != true || fact.Payload["default_encryption_enabled"] != true || fact.Payload["sse_kms_key_arn"] != "alias/team" || fact.Payload["bucket_key_enabled"] != true {
		t.Fatalf("confirmed posture fields: %v", fact.Payload)
	}
	for _, field := range []string{"policy_present", "policy_grants_public", "block_public_acls", "block_public_access_all"} {
		if _, present := fact.Payload[field]; present {
			t.Fatalf("unproved posture field %s: %v", field, fact.Payload)
		}
	}
}

func TestS3PostureFactEncodesDerivedPolicyFlags(t *testing.T) {
	present, public, crossAccount := true, false, true
	fact, err := NewS3BucketPostureFact(S3BucketPostureObservation{
		Boundary:  Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "s3", ScopeID: "scope", GenerationID: "generation", CollectorInstanceID: "instance", ClaimToken: "fence"},
		BucketARN: "arn:aws:s3:::assets", BucketName: "assets", SourceURI: "aws:source",
		PolicyPresent: &present, PolicyGrantsPublic: &public, PolicyGrantsCrossAccount: &crossAccount,
	})
	if err != nil || fact.Payload["policy_present"] != true || fact.Payload["policy_grants_public"] != false || fact.Payload["policy_grants_cross_account"] != true {
		t.Fatalf("derived policy fields not encoded: err=%v payload=%v", err, fact.Payload)
	}
	for _, field := range []string{"block_public_access_all", "block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets", "policy_is_public"} {
		if _, present := fact.Payload[field]; present {
			t.Fatalf("unproven posture field %q emitted", field)
		}
	}
}
