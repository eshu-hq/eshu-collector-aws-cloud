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

// Wave 1 s3 parity pins (eshu-hq/eshu#9296, Q4 bar items (a)+(b)). Each frozen
// value below is the in-tree envelope output for the shared fixture bucket
// ("parity-artifacts"), executed through the in-tree s3 scanner observation
// builders (bucketObservation, bucketPostureObservation, loggingRelationship)
// plus NewResourceEnvelope / NewS3BucketPostureEnvelope /
// NewRelationshipEnvelope.
//
// Re-derivation recipe: eshu origin/main 6ca3ad9294, throwaway package-s3
// probe TestZZWave1S3Oracle exercising those builders on the fixture model,
// `go test ./internal/collector/awscloud/service/s3/ -run TestZZWave1S3Oracle`
// from go/. Probe files deleted after the run; this test is the durable pin.
// Fixture boundary: account 123456789012, region us-east-1, scope
// "aws:123456789012:us-east-1", generation
// "aws:123456789012:us-east-1:parity:1", instance "aws-parity-8852".
const (
	frozenWave1S3ResourceKey = "39c6fbd9320e7e63200c8d1611f3ac3c8d2c096c2d40466c42cb600f94c02d06"
	frozenWave1S3PostureKey  = "97ae4a36aa7fd60adc765e7c66a0dbd17321d6f5f17a7c537010d860ac6f8815"
	frozenWave1S3LoggingKey  = "732354bb06a268c29add15e9a224b8e0b7bf06e6a81dd56bc2ae196822fd2c17"
)

// frozenWave1S3PosturePayload is the in-tree canonical s3_bucket_posture
// payload for the fixture bucket, including the block-public-access flags the
// satellite live path did not previously emit.
const frozenWave1S3PosturePayload = `{"account_id":"123456789012","acl_disabled":true,"block_public_access_all":true,"block_public_acls":true,"block_public_policy":true,"bucket_arn":"arn:aws:s3:::parity-artifacts","bucket_key_enabled":true,"bucket_name":"parity-artifacts","collector_instance_id":"aws-parity-8852","correlation_anchors":["arn:aws:s3:::parity-artifacts","parity-artifacts","s3://parity-artifacts"],"default_encryption_enabled":true,"encryption_algorithms":["aws:kms"],"ignore_public_acls":true,"logging_enabled":true,"logging_target_bucket":"parity-logs","mfa_delete_enabled":false,"object_ownership":["BucketOwnerEnforced"],"policy_grants_cross_account":false,"policy_grants_public":true,"policy_present":true,"region":"us-east-1","replication_enabled":true,"restrict_public_buckets":true,"service_kind":"s3","sse_kms_key_arn":"arn:aws:kms:us-east-1:123456789012:key/parity","versioning_enabled":true,"versioning_status":"Enabled"}`

// frozenWave1S3LoggingPayload is the in-tree canonical aws_relationship
// payload for the fixture bucket's server-access-log edge.
const frozenWave1S3LoggingPayload = `{"account_id":"123456789012","attributes":{"target_prefix":"logs/"},"collector_instance_id":"aws-parity-8852","region":"us-east-1","relationship_type":"s3_bucket_logs_to_bucket","service_kind":"s3","source_arn":"arn:aws:s3:::parity-artifacts","source_resource_id":"arn:aws:s3:::parity-artifacts","target_arn":"arn:aws:s3:::parity-logs","target_resource_id":"arn:aws:s3:::parity-logs","target_type":"aws_s3_bucket"}`

func wave1S3Boundary(t *testing.T) Boundary {
	t.Helper()
	return boundaryForParity(t,
		"aws:123456789012:us-east-1",
		"aws:123456789012:us-east-1:parity:1",
		"aws-parity-8852",
		catalog.ServiceS3)
}

// wave1S3ResourceObservation mirrors the in-tree bucketObservation output for
// the fixture bucket field for field, including every attribute the in-tree
// bucketAttributes mapper emits.
func wave1S3ResourceObservation(t *testing.T) ResourceObservation {
	t.Helper()
	return ResourceObservation{
		Boundary:     wave1S3Boundary(t),
		ARN:          "arn:aws:s3:::parity-artifacts",
		ResourceID:   "arn:aws:s3:::parity-artifacts",
		ResourceType: catalog.ResourceTypeS3Bucket,
		Name:         "parity-artifacts",
		Tags:         map[string]string{"Environment": "parity"},
		Attributes: map[string]any{
			"bucket_region":                 "us-east-1",
			"creation_time":                 time.Date(2026, 10, 20, 13, 0, 0, 0, time.UTC),
			"versioning_status":             "Enabled",
			"mfa_delete":                    "",
			"default_encryption_algorithms": []string{"aws:kms"},
			"kms_master_key_ids":            []string{"arn:aws:kms:us-east-1:123456789012:key/parity"},
			"bucket_key_enabled":            true,
			"block_public_acls":             true,
			"ignore_public_acls":            true,
			"block_public_policy":           true,
			"restrict_public_buckets":       true,
			"policy_is_public":              true,
			"ownership_controls":            []string{"BucketOwnerEnforced"},
			"website_enabled":               true,
			"website_has_index_document":    true,
			"website_has_error_document":    false,
			"website_redirect_host_name":    "",
			"website_routing_rule_count":    0,
			"logging_enabled":               true,
			"logging_target_bucket":         "parity-logs",
			"logging_target_prefix":         "logs/",
		},
		CorrelationAnchors: []string{
			"arn:aws:s3:::parity-artifacts",
			"parity-artifacts",
			"s3://parity-artifacts",
		},
		SourceURI:      "aws:s3:bucket/parity-artifacts",
		SourceRecordID: "arn:aws:s3:::parity-artifacts",
	}
}

// wave1S3PostureObservation mirrors the in-tree bucketPostureObservation
// output for the fixture bucket, including the block-public-access flags.
func wave1S3PostureObservation(t *testing.T) S3BucketPostureObservation {
	t.Helper()
	truth := true
	versioning := "Enabled"
	return S3BucketPostureObservation{
		Boundary:                    wave1S3Boundary(t),
		BucketARN:                   "arn:aws:s3:::parity-artifacts",
		BucketName:                  "parity-artifacts",
		PolicyPresent:               &truth,
		PolicyGrantsPublic:          &truth,
		PolicyGrantsCrossAccount:    new(bool),
		ReplicationEnabled:          &truth,
		LoggingEnabled:              &truth,
		LoggingTargetBucket:         "parity-logs",
		VersioningStatus:            &versioning,
		VersioningEnabled:           &truth,
		MFADeleteEnabled:            new(bool),
		ObjectOwnership:             []string{"BucketOwnerEnforced"},
		ACLDisabled:                 &truth,
		DefaultEncryptionEnabled:    &truth,
		EncryptionAlgorithms:        []string{"aws:kms"},
		SSEKMSKeyARN:                "arn:aws:kms:us-east-1:123456789012:key/parity",
		BucketKeyEnabled:            &truth,
		BlockPublicACLs:             &truth,
		IgnorePublicACLs:            &truth,
		BlockPublicPolicy:           &truth,
		RestrictPublicBuckets:       &truth,
		BlockPublicAccessAllEnabled: &truth,
		SourceURI:                   "aws:s3:bucket/parity-artifacts",
		SourceRecordID:              "arn:aws:s3:::parity-artifacts#posture",
	}
}

func wave1S3LoggingObservation(t *testing.T) RelationshipObservation {
	t.Helper()
	return RelationshipObservation{
		Boundary:         wave1S3Boundary(t),
		RelationshipType: catalog.RelationshipS3BucketLogsToBucket,
		SourceResourceID: "arn:aws:s3:::parity-artifacts",
		SourceARN:        "arn:aws:s3:::parity-artifacts",
		TargetResourceID: "arn:aws:s3:::parity-logs",
		TargetARN:        "arn:aws:s3:::parity-logs",
		TargetType:       catalog.ResourceTypeS3Bucket,
		Attributes:       map[string]any{"target_prefix": "logs/"},
		SourceURI:        "aws:s3:bucket/parity-artifacts",
		SourceRecordID:   "arn:aws:s3:::parity-artifacts->logging:parity-logs",
	}
}

func canonicalPayload(t *testing.T, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestWave1S3BucketResourceParity(t *testing.T) {
	t.Parallel()

	fact, err := NewResourceFact(wave1S3ResourceObservation(t))
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindResource || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.StableKey != frozenWave1S3ResourceKey {
		t.Fatalf("StableKey = %q, want in-tree frozen %q", fact.StableKey, frozenWave1S3ResourceKey)
	}
	for key, want := range map[string]any{
		"resource_type": catalog.ResourceTypeS3Bucket,
		"arn":           "arn:aws:s3:::parity-artifacts",
		"name":          "parity-artifacts",
		"region":        "us-east-1",
		"account_id":    "123456789012",
		"service_kind":  catalog.ServiceS3,
	} {
		if got := fact.Payload[key]; got != want {
			t.Fatalf("payload[%q] = %#v, want %#v", key, got, want)
		}
	}
	// The scanner-derived attributes must survive the emission path intact.
	// The encoder flattens the attribute content under the payload
	// "attributes" key, so parity pins that content rather than any wrapper.
	attrs, ok := fact.Payload["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("payload attributes content = %#v", fact.Payload["attributes"])
	}
	for _, key := range []string{
		"bucket_region", "creation_time", "versioning_status", "mfa_delete",
		"default_encryption_algorithms", "kms_master_key_ids", "bucket_key_enabled",
		"block_public_acls", "ignore_public_acls", "block_public_policy",
		"restrict_public_buckets", "policy_is_public", "ownership_controls",
		"website_enabled", "website_has_index_document", "website_has_error_document",
		"website_redirect_host_name", "website_routing_rule_count",
		"logging_enabled", "logging_target_bucket", "logging_target_prefix",
	} {
		if _, present := attrs[key]; !present {
			t.Fatalf("payload attributes miss %q: %v", key, canonicalPayload(t, attrs))
		}
	}
	if got := canonicalPayload(t, attrs); got != wave1S3OracleAttrs(t) {
		t.Fatalf("attributes = %s, want in-tree %s", got, wave1S3OracleAttrs(t))
	}
	decoded, err := factschema.DecodeAWSResource(factschema.Envelope{
		FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload,
	})
	if err != nil || decoded.ResourceType != catalog.ResourceTypeS3Bucket {
		t.Fatalf("typed decode = %+v, %v", decoded, err)
	}
}

// wave1S3OracleAttrs is the in-tree canonical attribute content for the
// fixture bucket (oracle S3_RESOURCE payload, attributes section).
func wave1S3OracleAttrs(t *testing.T) string {
	t.Helper()
	attrs := map[string]any{
		"bucket_region":                 "us-east-1",
		"creation_time":                 "2026-10-20T13:00:00Z",
		"versioning_status":             "Enabled",
		"mfa_delete":                    "",
		"default_encryption_algorithms": []string{"aws:kms"},
		"kms_master_key_ids":            []string{"arn:aws:kms:us-east-1:123456789012:key/parity"},
		"bucket_key_enabled":            true,
		"block_public_acls":             true,
		"ignore_public_acls":            true,
		"block_public_policy":           true,
		"restrict_public_buckets":       true,
		"policy_is_public":              true,
		"ownership_controls":            []string{"BucketOwnerEnforced"},
		"website_enabled":               true,
		"website_has_index_document":    true,
		"website_has_error_document":    false,
		"website_redirect_host_name":    "",
		"website_routing_rule_count":    0,
		"logging_enabled":               true,
		"logging_target_bucket":         "parity-logs",
		"logging_target_prefix":         "logs/",
	}
	raw, err := json.Marshal(attrs)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestWave1S3BucketPostureParity(t *testing.T) {
	t.Parallel()

	fact, err := NewS3BucketPostureFact(wave1S3PostureObservation(t))
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindS3BucketPosture || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.StableKey != frozenWave1S3PostureKey {
		t.Fatalf("StableKey = %q, want in-tree frozen %q", fact.StableKey, frozenWave1S3PostureKey)
	}
	if got := canonicalPayload(t, fact.Payload); got != frozenWave1S3PosturePayload {
		t.Fatalf("payload = %s, want in-tree %s", got, frozenWave1S3PosturePayload)
	}
	decoded, err := factschema.DecodeS3BucketPosture(factschema.Envelope{
		FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload,
	})
	if err != nil || decoded.BucketName == nil || *decoded.BucketName != "parity-artifacts" {
		t.Fatalf("typed decode = %+v, %v", decoded, err)
	}
	if decoded.BlockPublicACLs == nil || !*decoded.BlockPublicACLs {
		t.Fatalf("typed decode block_public_acls = %+v", decoded.BlockPublicACLs)
	}
}

func TestWave1S3LoggingRelationshipParity(t *testing.T) {
	t.Parallel()

	fact, err := NewRelationshipFact(wave1S3LoggingObservation(t))
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindRelationship || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.StableKey != frozenWave1S3LoggingKey {
		t.Fatalf("StableKey = %q, want in-tree frozen %q", fact.StableKey, frozenWave1S3LoggingKey)
	}
	if got := canonicalPayload(t, fact.Payload); got != frozenWave1S3LoggingPayload {
		t.Fatalf("payload = %s, want in-tree %s", got, frozenWave1S3LoggingPayload)
	}
	decoded, err := factschema.DecodeAWSRelationship(factschema.Envelope{
		FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload,
	})
	if err != nil || decoded.RelationshipType != catalog.RelationshipS3BucketLogsToBucket {
		t.Fatalf("typed decode = %+v, %v", decoded, err)
	}
}

func TestWave1S3FactsRejectHostileInput(t *testing.T) {
	t.Parallel()

	observation := wave1S3ResourceObservation(t)
	observation.ARN = ""
	observation.ResourceID = "  "
	if _, err := NewResourceFact(observation); err == nil {
		t.Fatal("blank resource identity accepted")
	}
	posture := wave1S3PostureObservation(t)
	posture.BucketARN = ""
	posture.BucketName = "  "
	if _, err := NewS3BucketPostureFact(posture); err == nil {
		t.Fatal("blank posture bucket identity accepted")
	}
	relationship := wave1S3LoggingObservation(t)
	relationship.SourceResourceID = ""
	relationship.SourceARN = "  "
	if _, err := NewRelationshipFact(relationship); err == nil {
		t.Fatal("blank relationship source accepted")
	}
}
