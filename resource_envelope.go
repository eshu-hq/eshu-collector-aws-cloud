// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/factschema"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// NewResourceFact builds one typed aws_resource fact from a service observation.
// Service scanners must redact sensitive values before constructing the
// observation; this seam applies the SDK's fact-scoped payload safety policy
// and rejects unsafe URIs before returning the fact.
func NewResourceFact(observation ResourceObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(observation.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	arn := strings.TrimSpace(observation.ARN)
	resourceID := strings.TrimSpace(observation.ResourceID)
	if arn == "" && resourceID == "" {
		return sdk.Fact{}, fmt.Errorf("aws resource observation requires arn or resource_id")
	}
	if resourceID == "" {
		resourceID = arn
	}
	resourceType := strings.TrimSpace(observation.ResourceType)
	if resourceType == "" {
		return sdk.Fact{}, fmt.Errorf("aws resource observation requires resource_type")
	}
	uri := strings.TrimSpace(observation.SourceURI)
	if uri == "" {
		return sdk.Fact{}, fmt.Errorf("aws resource observation requires source_uri")
	}
	if err := checkSourceURI(uri); err != nil {
		return sdk.Fact{}, err
	}

	boundary := observation.Boundary
	stableKey, err := resourceStableKey(boundary.AccountID, boundary.Region, resourceID, resourceType)
	if err != nil {
		return sdk.Fact{}, err
	}
	attributes, err := snapshotResourceAttributes(observation.Attributes)
	if err != nil {
		return sdk.Fact{}, err
	}
	tags := cloneResourceTags(observation.Tags)
	payload, err := factschema.EncodeAWSResource(awsv1.Resource{
		AccountID:    boundary.AccountID,
		Region:       boundary.Region,
		ServiceKind:  resourceStringPointer(strings.TrimSpace(boundary.ServiceKind)),
		ARN:          resourceStringPointer(arn),
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Name:         resourceStringPointer(strings.TrimSpace(observation.Name)),
		State:        resourceStringPointer(strings.TrimSpace(observation.State)),
		Tags:         &tags,
		Attributes: map[string]any{
			"collector_instance_id": boundary.CollectorInstanceID,
			"attributes":            attributes,
		},
		CorrelationAnchors: normalizedResourceAnchors(observation.CorrelationAnchors, arn, resourceID),
	})
	if err != nil {
		return sdk.Fact{}, errors.New("encode aws_resource payload failed")
	}
	observedAt := boundary.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	recordID := strings.TrimSpace(observation.SourceRecordID)
	if recordID == "" {
		recordID = resourceID
	}
	fact := sdk.Fact{
		Kind:             AWSKindResource,
		SchemaVersion:    "1.0.0",
		StableKey:        stableKey,
		SourceConfidence: sdk.SourceConfidenceReported,
		ObservedAt:       observedAt,
		SourceRef: sdk.SourceRef{
			SourceSystem: SourceSystem,
			ScopeID:      boundary.ScopeID,
			GenerationID: boundary.GenerationID,
			FactKey:      stableKey,
			URI:          uri,
			RecordID:     recordID,
		},
		Payload: payload,
	}
	// The SDK validates the emitted payload in its fact context. Its AWS
	// exception admits only exact Lambda/ECS marker shapes; other sensitive
	// fields retain the ordinary recursive denial rule.
	if err := sdk.ValidateFactPayload(fact); err != nil {
		return sdk.Fact{}, fmt.Errorf("aws_resource payload is not share-safe: %w", err)
	}
	return fact, nil
}

func validateResourceBoundary(boundary Boundary) error {
	for _, required := range []struct{ name, value string }{
		{"account_id", boundary.AccountID},
		{"region", boundary.Region},
		{"service_kind", boundary.ServiceKind},
		{"scope_id", boundary.ScopeID},
		{"generation_id", boundary.GenerationID},
		{"collector_instance_id", boundary.CollectorInstanceID},
	} {
		if strings.TrimSpace(required.value) == "" {
			return fmt.Errorf("aws observation requires %s", required.name)
		}
	}
	if boundary.FencingToken <= 0 && strings.TrimSpace(boundary.ClaimToken) == "" {
		return fmt.Errorf("aws observation requires claim fencing token")
	}
	return nil
}

func resourceStableKey(accountID, region, resourceID, resourceType string) (string, error) {
	record := map[string]any{
		"fact_type": AWSKindResource,
		"identity": map[string]any{
			"account_id":    accountID,
			"region":        region,
			"resource_id":   resourceID,
			"resource_type": resourceType,
		},
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", errors.New("encode aws_resource identity failed")
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func normalizedResourceAnchors(values []string, fallback ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(fallback))
	anchors := make([]string, 0, len(values)+len(fallback))
	for _, value := range append(append([]string(nil), values...), fallback...) {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		anchors = append(anchors, trimmed)
	}
	return anchors
}

// snapshotResourceAttributes copies the JSON representation that will be
// emitted. UseNumber retains large integer digits exactly; time.Time and
// custom marshalers become their wire values, with no pointers back to callers.
func snapshotResourceAttributes(input map[string]any) (map[string]any, error) {
	if len(input) == 0 {
		return nil, nil
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, errors.New("encode aws_resource attributes failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var cloned map[string]any
	if err := decoder.Decode(&cloned); err != nil {
		return nil, errors.New("decode aws_resource attributes failed")
	}
	return cloned, nil
}

func cloneResourceTags(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func resourceStringPointer(value string) *string { return &value }
