// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/factschema"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

func s3BucketPostureDeclaration() sdk.FactDeclaration {
	return sdk.FactDeclaration{Kind: AWSKindS3BucketPosture, SchemaVersions: []string{"1.0.0"}, SourceConfidence: []sdk.SourceConfidence{sdk.SourceConfidenceReported}}
}

// NewS3BucketPostureFact builds the reported typed bucket posture fact.
func NewS3BucketPostureFact(observation S3BucketPostureObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(observation.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	arn := strings.TrimSpace(observation.BucketARN)
	name := strings.TrimSpace(observation.BucketName)
	if arn == "" && name == "" {
		return sdk.Fact{}, fmt.Errorf("s3 bucket posture requires bucket_arn or bucket_name")
	}
	if arn != "" {
		prefix, bucket, ok := strings.Cut(arn, ":::")
		parts := strings.Split(prefix, ":")
		if !ok || len(parts) != 3 || parts[0] != "arn" || parts[1] == "" || parts[2] != "s3" || bucket == "" || (name != "" && name != bucket) {
			return sdk.Fact{}, fmt.Errorf("s3 bucket posture has inconsistent bucket identity")
		}
	}
	uri := strings.TrimSpace(observation.SourceURI)
	if uri == "" {
		return sdk.Fact{}, fmt.Errorf("s3 bucket posture requires source_uri")
	}
	if err := checkSourceURI(uri); err != nil {
		return sdk.Fact{}, err
	}
	identity := arn
	if identity == "" {
		identity = name
	}
	keyRecord := map[string]any{"fact_type": AWSKindS3BucketPosture, "identity": map[string]any{
		"account_id": observation.Boundary.AccountID, "bucket": identity, "region": observation.Boundary.Region,
	}}
	keyBytes, err := json.Marshal(keyRecord)
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode s3 posture identity: %w", err)
	}
	keyHash := sha256.Sum256(keyBytes)
	stableKey := hex.EncodeToString(keyHash[:])
	anchors := normalizedResourceAnchors(nil, arn, name)
	if name != "" {
		anchors = normalizedResourceAnchors(anchors, "s3://"+name)
	}
	var arnValue, nameValue *string
	if arn != "" {
		arnValue = &arn
	}
	if name != "" {
		nameValue = &name
	}
	service := strings.TrimSpace(observation.Boundary.ServiceKind)
	instance := strings.TrimSpace(observation.Boundary.CollectorInstanceID)
	payload, err := factschema.EncodeS3BucketPosture(awsv1.S3BucketPosture{
		AccountID: observation.Boundary.AccountID, Region: observation.Boundary.Region,
		ServiceKind: &service, CollectorInstanceID: &instance,
		BucketARN: arnValue, BucketName: nameValue, ReplicationEnabled: observation.ReplicationEnabled,
		PolicyPresent: observation.PolicyPresent, PolicyGrantsPublic: observation.PolicyGrantsPublic,
		PolicyGrantsCrossAccount: observation.PolicyGrantsCrossAccount,
		CorrelationAnchors:       anchors,
	})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode s3_bucket_posture payload: %w", err)
	}
	if err := sdk.ValidateShareSafeKeys(payload); err != nil {
		return sdk.Fact{}, fmt.Errorf("s3_bucket_posture payload contains sensitive key: %w", err)
	}
	observedAt := observation.Boundary.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	recordID := strings.TrimSpace(observation.SourceRecordID)
	if recordID == "" {
		recordID = identity + "#posture"
	}
	return sdk.Fact{
		Kind: AWSKindS3BucketPosture, SchemaVersion: "1.0.0", StableKey: stableKey,
		SourceConfidence: sdk.SourceConfidenceReported, ObservedAt: observedAt,
		SourceRef: sdk.SourceRef{SourceSystem: SourceSystem, ScopeID: observation.Boundary.ScopeID,
			GenerationID: observation.Boundary.GenerationID, FactKey: stableKey, URI: uri, RecordID: recordID},
		Payload: payload,
	}, nil
}
