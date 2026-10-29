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

// AppendLiveRDSPostures appends typed posture facts within the claim's count and payload limits.
func AppendLiveRDSPostures(result sdk.Result, observations []RDSPostureObservation, sourceURI string, limits ResourceUse) (sdk.Result, error) {
	if result.State != sdk.ResultComplete && result.State != sdk.ResultPartial {
		return result, nil
	}
	if limits.MaxRecordsPerClaim <= 0 {
		limits.MaxRecordsPerClaim = DefaultResourceUse().MaxRecordsPerClaim
	}
	if limits.MaxPayloadBytes <= 0 {
		limits.MaxPayloadBytes = DefaultResourceUse().MaxPayloadBytes
	}
	if strings.TrimSpace(result.Claim.FencingToken) == "" {
		return sdk.Result{}, fmt.Errorf("live AWS claim requires fencing token")
	}
	seen := make(map[string]struct{}, len(result.Facts)+len(observations))
	for _, fact := range result.Facts {
		seen[fact.Kind+"\x00"+fact.StableKey] = struct{}{}
	}
	for _, observation := range observations {
		observation.Boundary.ScopeID = result.Claim.Scope.ID
		observation.Boundary.GenerationID = result.Claim.GenerationID
		observation.Boundary.CollectorInstanceID = result.Claim.InstanceID
		observation.Boundary.ClaimToken = result.Claim.FencingToken
		observation.Boundary.ObservedAt = result.Generation.ObservedAt
		observation.SourceURI = sourceURI
		fact, err := NewRDSPostureFact(observation)
		if err != nil {
			return sdk.Result{}, err
		}
		key := fact.Kind + "\x00" + fact.StableKey
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		if len(result.Facts) >= limits.MaxRecordsPerClaim {
			return terminalResult(result.Claim, result.Generation.ObservedAt, "record-budget-exceeded"), nil
		}
		encoded, err := json.Marshal(fact.Payload)
		if err != nil {
			return sdk.Result{}, fmt.Errorf("encode RDS posture payload: %w", err)
		}
		if len(encoded) > limits.MaxPayloadBytes {
			return terminalResult(result.Claim, result.Generation.ObservedAt, "payload-budget-exceeded"), nil
		}
		result.Facts = append(result.Facts, fact)
	}
	for i := range result.Statuses {
		result.Statuses[i].FactCount = len(result.Facts)
	}
	return result, nil
}

// NewRDSPostureFact constructs a claim-bound typed fact for RDS instance or cluster posture.
func NewRDSPostureFact(observation RDSPostureObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(observation.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	if observation.Boundary.ServiceKind != "rds" {
		return sdk.Fact{}, fmt.Errorf("RDS posture requires rds service boundary")
	}
	arn := strings.TrimSpace(observation.ARN)
	id := strings.TrimSpace(observation.ResourceID)
	if arn == "" && id == "" {
		return sdk.Fact{}, fmt.Errorf("RDS posture requires arn or resource_id")
	}
	if id == "" {
		id = arn
	}
	resourceType := strings.TrimSpace(observation.ResourceType)
	if resourceType != "aws_rds_db_instance" && resourceType != "aws_rds_db_cluster" {
		return sdk.Fact{}, fmt.Errorf("RDS posture requires supported resource_type")
	}
	if strings.TrimSpace(observation.SourceURI) == "" {
		return sdk.Fact{}, fmt.Errorf("RDS posture requires source_uri")
	}
	if err := checkSourceURI(observation.SourceURI); err != nil {
		return sdk.Fact{}, err
	}
	keyRecord := map[string]any{"fact_type": AWSKindRDSInstancePosture, "identity": map[string]any{
		"account_id": observation.Boundary.AccountID, "region": observation.Boundary.Region,
		"resource_id": id, "resource_type": resourceType,
	}}
	encodedKey, err := json.Marshal(keyRecord)
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode RDS posture identity: %w", err)
	}
	sum := sha256.Sum256(encodedKey)
	stableKey := hex.EncodeToString(sum[:])
	parameters := append([]string(nil), observation.ParameterGroups...)
	options := append([]string(nil), observation.OptionGroups...)
	payload, err := factschema.EncodeRDSInstancePosture(awsv1.RDSInstancePosture{
		AccountID: observation.Boundary.AccountID, Region: observation.Boundary.Region,
		ServiceKind: resourceStringPointer("rds"), CollectorInstanceID: resourceStringPointer(observation.Boundary.CollectorInstanceID),
		ARN: resourceStringPointer(arn), ResourceID: resourceStringPointer(id), ResourceType: resourceStringPointer(resourceType),
		Identifier: resourceStringPointer(strings.TrimSpace(observation.Identifier)), Engine: resourceStringPointer(strings.TrimSpace(observation.Engine)),
		PubliclyAccessible: observation.PubliclyAccessible, StorageEncrypted: observation.StorageEncrypted,
		KMSKeyID:                         resourceStringPointer(strings.TrimSpace(observation.KMSKeyID)),
		IAMDatabaseAuthenticationEnabled: observation.IAMDatabaseAuthenticationEnabled,
		MultiAZ:                          observation.MultiAZ, DeletionProtection: observation.DeletionProtection,
		BackupRetentionPeriod:            observation.BackupRetentionPeriod,
		PerformanceInsightsEnabled:       observation.PerformanceInsightsEnabled,
		PerformanceInsightsRetentionDays: observation.PerformanceInsightsRetentionDays,
		PerformanceInsightsKMSKeyID:      resourceStringPointer(strings.TrimSpace(observation.PerformanceInsightsKMSKeyID)),
		CACertificateIdentifier:          resourceStringPointer(strings.TrimSpace(observation.CACertificateIdentifier)),
		ParameterGroups:                  parameters, OptionGroups: options,
		CorrelationAnchors: normalizedResourceAnchors(nil, arn, id, strings.TrimSpace(observation.Identifier)),
	})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode RDS posture payload: %w", err)
	}
	if err := sdk.ValidateShareSafeKeys(payload); err != nil {
		return sdk.Fact{}, fmt.Errorf("RDS posture payload contains unredacted sensitive key: %w", err)
	}
	observedAt := observation.Boundary.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	recordID := strings.TrimSpace(observation.SourceRecordID)
	if recordID == "" {
		recordID = resourceType + ":" + id
	}
	return sdk.Fact{
		Kind: AWSKindRDSInstancePosture, SchemaVersion: "1.0.0", StableKey: stableKey,
		SourceConfidence: sdk.SourceConfidenceReported, ObservedAt: observedAt,
		SourceRef: sdk.SourceRef{
			SourceSystem: SourceSystem, ScopeID: observation.Boundary.ScopeID,
			GenerationID: observation.Boundary.GenerationID, FactKey: stableKey,
			URI: observation.SourceURI, RecordID: recordID,
		}, Payload: payload,
	}, nil
}
