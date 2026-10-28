// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/factschema"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// NewResourceFact builds one typed aws_resource fact from a service observation.
// Service scanners must redact sensitive values before constructing the
// observation; this seam rejects sensitive-shaped payload keys and unsafe URIs.
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
	tags := observation.Tags
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
			"attributes":            observation.Attributes,
		},
		CorrelationAnchors: normalizedResourceAnchors(observation.CorrelationAnchors, arn, resourceID),
	})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode aws_resource payload: %w", err)
	}
	// Check JSON safety before walking the value graph: encoding/json rejects
	// cycles and unsupported types. Then copy every map, slice, and pointer
	// before validating, so later caller mutation cannot change the fact.
	if _, err := json.Marshal(payload); err != nil {
		return sdk.Fact{}, fmt.Errorf("encode aws_resource payload: %w", err)
	}
	clonedPayload, ok := cloneResourceJSONValue(reflect.ValueOf(payload)).Interface().(map[string]any)
	if !ok {
		return sdk.Fact{}, fmt.Errorf("copy aws_resource payload: unexpected root type")
	}
	payload = clonedPayload
	// Validate the JSON shape the host will receive. The SDK key walker only
	// traverses map[string]any; tags and service fields may contain typed maps.
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode aws_resource payload: %w", err)
	}
	var sharedPayload any
	if err := json.Unmarshal(encodedPayload, &sharedPayload); err != nil {
		return sdk.Fact{}, fmt.Errorf("decode aws_resource validation payload: %w", err)
	}
	if err := sdk.ValidateShareSafeKeys(sharedPayload); err != nil {
		return sdk.Fact{}, fmt.Errorf("aws_resource payload contains unredacted sensitive key: %w", err)
	}
	observedAt := boundary.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	recordID := strings.TrimSpace(observation.SourceRecordID)
	if recordID == "" {
		recordID = resourceID
	}
	return sdk.Fact{
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
	}, nil
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
	if boundary.FencingToken <= 0 {
		return fmt.Errorf("aws observation fencing_token must be positive")
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
		return "", fmt.Errorf("encode aws_resource identity: %w", err)
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

// cloneResourceJSONValue copies JSON-safe data without coercing large integers
// through float64. The earlier Marshal call rejects cycles and unsupported
// values before this recursive walk.
func cloneResourceJSONValue(value reflect.Value) reflect.Value {
	if !value.IsValid() {
		return value
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		cloned := reflect.New(value.Type()).Elem()
		cloned.Set(cloneResourceJSONValue(value.Elem()))
		return cloned
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		cloned := reflect.New(value.Type().Elem())
		cloned.Elem().Set(cloneResourceJSONValue(value.Elem()))
		return cloned
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		cloned := reflect.MakeMapWithSize(value.Type(), value.Len())
		iter := value.MapRange()
		for iter.Next() {
			cloned.SetMapIndex(cloneResourceJSONValue(iter.Key()), cloneResourceJSONValue(iter.Value()))
		}
		return cloned
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		cloned := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for index := 0; index < value.Len(); index++ {
			cloned.Index(index).Set(cloneResourceJSONValue(value.Index(index)))
		}
		return cloned
	case reflect.Array:
		cloned := reflect.New(value.Type()).Elem()
		for index := 0; index < value.Len(); index++ {
			cloned.Index(index).Set(cloneResourceJSONValue(value.Index(index)))
		}
		return cloned
	case reflect.Struct:
		cloned := reflect.New(value.Type()).Elem()
		cloned.Set(value)
		for index := 0; index < value.NumField(); index++ {
			if cloned.Field(index).CanSet() {
				cloned.Field(index).Set(cloneResourceJSONValue(value.Field(index)))
			}
		}
		return cloned
	default:
		return value
	}
}

func resourceStringPointer(value string) *string { return &value }
