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

// NewRelationshipFact builds the typed AWS relationship reported by an API.
func NewRelationshipFact(observation RelationshipObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(observation.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	kind := strings.TrimSpace(observation.RelationshipType)
	sourceID := strings.TrimSpace(observation.SourceResourceID)
	targetID := strings.TrimSpace(observation.TargetResourceID)
	sourceARN := strings.TrimSpace(observation.SourceARN)
	targetARN := strings.TrimSpace(observation.TargetARN)
	if sourceID == "" {
		sourceID = sourceARN
	}
	if targetID == "" {
		targetID = targetARN
	}
	if kind == "" || sourceID == "" || targetID == "" {
		return sdk.Fact{}, fmt.Errorf("aws relationship requires type and source/target identity")
	}
	uri := strings.TrimSpace(observation.SourceURI)
	if uri == "" {
		return sdk.Fact{}, fmt.Errorf("aws relationship requires source_uri")
	}
	if err := checkSourceURI(uri); err != nil {
		return sdk.Fact{}, err
	}
	attrs, err := snapshotResourceAttributes(observation.Attributes)
	if err != nil {
		return sdk.Fact{}, err
	}
	identity := map[string]any{
		"account_id": observation.Boundary.AccountID, "region": observation.Boundary.Region,
		"relationship_type": kind, "source_resource_id": sourceID, "target_resource_id": targetID,
	}
	keyRecord := map[string]any{"fact_type": AWSKindRelationship, "identity": identity}
	encodedKey, err := json.Marshal(keyRecord)
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode aws relationship identity: %w", err)
	}
	digest := sha256.Sum256(encodedKey)
	stableKey := hex.EncodeToString(digest[:])
	payload, err := factschema.EncodeAWSRelationship(awsv1.Relationship{
		AccountID: observation.Boundary.AccountID, Region: observation.Boundary.Region,
		RelationshipType: kind, SourceResourceID: sourceID, TargetResourceID: targetID,
		SourceARN: resourceStringPointer(sourceARN), TargetARN: resourceStringPointer(targetARN),
		TargetType: resourceStringPointer(strings.TrimSpace(observation.TargetType)),
		Attributes: map[string]any{
			"service_kind":          strings.TrimSpace(observation.Boundary.ServiceKind),
			"collector_instance_id": observation.Boundary.CollectorInstanceID,
			"attributes":            attrs,
		},
	})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode aws relationship payload: %w", err)
	}
	wire, err := json.Marshal(payload)
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode aws relationship validation payload: %w", err)
	}
	var shared any
	if err := json.Unmarshal(wire, &shared); err != nil {
		return sdk.Fact{}, fmt.Errorf("decode aws relationship validation payload: %w", err)
	}
	if err := sdk.ValidateShareSafeKeys(shared); err != nil {
		return sdk.Fact{}, fmt.Errorf("aws relationship payload contains unredacted sensitive key: %w", err)
	}
	observedAt := observation.Boundary.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	recordID := strings.TrimSpace(observation.SourceRecordID)
	if recordID == "" {
		recordID = sourceID + "->" + targetID
	}
	return sdk.Fact{
		Kind: AWSKindRelationship, SchemaVersion: "1.0.0", StableKey: stableKey,
		SourceConfidence: sdk.SourceConfidenceReported, ObservedAt: observedAt,
		SourceRef: sdk.SourceRef{
			SourceSystem: SourceSystem, ScopeID: observation.Boundary.ScopeID,
			GenerationID: observation.Boundary.GenerationID, FactKey: stableKey, URI: uri, RecordID: recordID,
		},
		Payload: payload,
	}, nil
}
