// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/factschema"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// AppendLiveWarnings adds claim-bound, typed aws_warning evidence for reviewed
// optional API denials. Operation, resource and effect participate in identity.
func AppendLiveWarnings(result sdk.Result, warnings []WarningObservation, sourceURI string, limits ResourceUse) (sdk.Result, error) {
	if result.State != sdk.ResultPartial {
		return result, nil
	}
	if limits.MaxRecordsPerClaim <= 0 {
		limits.MaxRecordsPerClaim = DefaultResourceUse().MaxRecordsPerClaim
	}
	if limits.MaxPayloadBytes <= 0 {
		limits.MaxPayloadBytes = DefaultResourceUse().MaxPayloadBytes
	}
	if err := checkSourceURI(sourceURI); err != nil {
		return sdk.Result{}, err
	}
	seen := make(map[string]struct{}, len(result.Facts)+len(warnings))
	for _, fact := range result.Facts {
		seen[fact.Kind+"\x00"+fact.StableKey] = struct{}{}
	}
	for _, warning := range warnings {
		warning.Boundary.ScopeID = result.Claim.Scope.ID
		warning.Boundary.GenerationID = result.Claim.GenerationID
		warning.Boundary.CollectorInstanceID = result.Claim.InstanceID
		warning.Boundary.ClaimToken = result.Claim.FencingToken
		warning.Boundary.ObservedAt = result.Generation.ObservedAt
		warning.SourceURI = sourceURI
		fact, err := NewWarningFact(warning)
		if err != nil {
			return sdk.Result{}, err
		}
		identity := fact.Kind + "\x00" + fact.StableKey
		if _, exists := seen[identity]; exists {
			continue
		}
		seen[identity] = struct{}{}
		if len(result.Facts) >= limits.MaxRecordsPerClaim {
			return terminalResult(result.Claim, result.Generation.ObservedAt, "record-budget-exceeded"), nil
		}
		encoded, err := json.Marshal(fact.Payload)
		if err != nil {
			return sdk.Result{}, fmt.Errorf("encode aws warning payload: %w", err)
		}
		if len(encoded) > limits.MaxPayloadBytes {
			return terminalResult(result.Claim, result.Generation.ObservedAt, "payload-budget-exceeded"), nil
		}
		result.Facts = append(result.Facts, fact)
		for i := range result.Statuses {
			result.Statuses[i].FactCount = len(result.Facts)
			if result.Statuses[i].Class == sdk.StatusWarning {
				result.Statuses[i].WarningCount++
			}
		}
	}
	return result, nil
}

// NewWarningFact creates a bounded aws_warning fact with operation, resource
// and effect in its stable identity, preventing separate denied reads colliding.
func NewWarningFact(w WarningObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(w.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	operation, _ := w.Attributes["operation"].(string)
	resource, _ := w.Attributes["resource"].(string)
	effect, _ := w.Attributes["effect"].(string)
	if strings.TrimSpace(w.WarningKind) == "" || operation == "" || resource == "" || effect == "" {
		return sdk.Fact{}, fmt.Errorf("aws warning requires kind, operation, resource and effect")
	}
	if err := checkSourceURI(w.SourceURI); err != nil {
		return sdk.Fact{}, err
	}
	identity := map[string]string{
		"kind": AWSKindWarning, "account": w.Boundary.AccountID,
		"region": w.Boundary.Region, "service": w.Boundary.ServiceKind,
		"generation": w.Boundary.GenerationID, "warning_kind": w.WarningKind,
		"operation": operation, "resource": resource, "effect": effect,
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode aws warning identity: %w", err)
	}
	sum := sha256.Sum256(encoded)
	key := hex.EncodeToString(sum[:])
	attrs, err := snapshotResourceAttributes(w.Attributes)
	if err != nil {
		return sdk.Fact{}, err
	}
	payload, err := factschema.EncodeAWSWarning(awsv1.Warning{
		AccountID: w.Boundary.AccountID, Region: w.Boundary.Region,
		ServiceKind:         resourceStringPointer(w.Boundary.ServiceKind),
		CollectorInstanceID: resourceStringPointer(w.Boundary.CollectorInstanceID),
		WarningKind:         w.WarningKind, ErrorClass: resourceStringPointer(w.ErrorClass),
		Message: resourceStringPointer(w.Message), Attributes: attrs,
	})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode aws warning payload: %w", err)
	}
	if err := sdk.ValidateShareSafeKeys(payload); err != nil {
		return sdk.Fact{}, err
	}
	recordID := strings.TrimSpace(w.SourceRecordID)
	if recordID == "" {
		recordID = operation + ":" + resource
	}
	return sdk.Fact{
		Kind: AWSKindWarning, SchemaVersion: "1.0.0", StableKey: key,
		SourceConfidence: sdk.SourceConfidenceReported, ObservedAt: w.Boundary.ObservedAt,
		SourceRef: sdk.SourceRef{SourceSystem: SourceSystem, ScopeID: w.Boundary.ScopeID,
			GenerationID: w.Boundary.GenerationID, FactKey: key, URI: w.SourceURI,
			RecordID: recordID}, Payload: payload,
	}, nil
}
