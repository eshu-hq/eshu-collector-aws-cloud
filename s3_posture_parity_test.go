// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	"github.com/eshu-hq/eshu-sdk/factschema"
)

// frozenS3BucketPostureKey is the in-tree stable key for the shared-fixture
// bucket (go/internal/collector/awscloud/source_parity_8852_test.go,
// parity8852S3PostureKey). The already-ported satellite builder must
// reproduce it byte for byte from the same fixture section. Re-derivation
// recipe (oracle commit, command, fixture hash):
// testdata/stable-key-provenance.md.
const frozenS3BucketPostureKey = "97ae4a36aa7fd60adc765e7c66a0dbd17321d6f5f17a7c537010d860ac6f8815"

func TestS3BucketPostureFactSharedFixtureParity(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("testdata/8852-parity-awscloud.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ScopeID             string `json:"scope_id"`
		GenerationID        string `json:"generation_id"`
		CollectorInstanceID string `json:"collector_instance_id"`
		S3Posture           struct {
			BucketARN           string `json:"bucket_arn"`
			BucketName          string `json:"bucket_name"`
			VersioningStatus    string `json:"versioning_status"`
			VersioningEnabled   bool   `json:"versioning_enabled"`
			SSEKMSKeyARN        string `json:"sse_kms_key_arn"`
			LoggingTargetBucket string `json:"logging_target_bucket"`
		} `json:"s3_posture"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	in := fixture.S3Posture
	enabled := true
	fact, err := NewS3BucketPostureFact(S3BucketPostureObservation{
		Boundary:                 boundaryForParity(t, fixture.ScopeID, fixture.GenerationID, fixture.CollectorInstanceID, catalog.ServiceS3),
		BucketARN:                in.BucketARN,
		BucketName:               in.BucketName,
		VersioningStatus:         &in.VersioningStatus,
		VersioningEnabled:        &in.VersioningEnabled,
		DefaultEncryptionEnabled: &enabled,
		EncryptionAlgorithms:     []string{"aws:kms"},
		SSEKMSKeyARN:             in.SSEKMSKeyARN,
		LoggingTargetBucket:      in.LoggingTargetBucket,
		SourceURI:                "aws:s3:bucket/parity-artifacts",
		SourceRecordID:           "s3-posture-row-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindS3BucketPosture || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.StableKey != frozenS3BucketPostureKey {
		t.Fatalf("StableKey = %q, want in-tree frozen %q", fact.StableKey, frozenS3BucketPostureKey)
	}
	if got, want := fact.Payload["bucket_name"], in.BucketName; got != want {
		t.Fatalf("bucket_name = %#v, want %#v", got, want)
	}
	decoded, err := factschema.DecodeS3BucketPosture(factschema.Envelope{
		FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload,
	})
	if err != nil || decoded.BucketName == nil || *decoded.BucketName != in.BucketName {
		t.Fatalf("typed decode = %+v, %v", decoded, err)
	}
}
