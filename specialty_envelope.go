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
)

// This file is the Wave 0 specialty envelope seam (eshu-hq/eshu#9296): the
// satellite-side builder surface for the nine blocked in-tree envelopes
// listed in NOT_PORTED.md (envelope.go, dns_envelope.go,
// ec2_posture_envelope.go, iam_permission_envelope.go,
// resource_policy_permission_envelope.go, posture_envelope.go,
// s3_posture_envelope.go, s3_external_principal_grant_envelope.go,
// security_group_rule_envelope.go).
//
// Each specialty kind below emits through the same factschema encoders the
// in-tree builders use, with the same fact-type string and stable-key
// identity the in-tree facts.StableID derives, so a shared fixture yields
// byte-identical stable keys on both sides. Scanner reads that feed these
// builders land per kind in later waves; this seam carries no live reads.

// specialtyStableKey derives the durable fact identity for one specialty
// observation. It reproduces the in-tree facts.StableID bytes exactly: the
// sha256 of {"fact_type":..., "identity":...} with encoding/json map-key
// ordering. Identity values stay JSON scalars (strings, bools, nil, integer
// types), for which the in-tree normalizer is the identity function, so no
// separate normalization pass can drift the bytes.
func specialtyStableKey(factType string, identity map[string]any) (string, error) {
	record := map[string]any{"fact_type": factType, "identity": identity}
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("encode specialty identity: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// specialtyFact assembles one SDK fact from an encoded specialty payload.
// Service scanners must redact sensitive values before constructing the
// observation; this seam rejects sensitive-shaped payload keys the same way
// the resource seam does.
func specialtyFact(kind, stableKey string, boundary Boundary, sourceURI, recordID string, payload map[string]any) (sdk.Fact, error) {
	uri := strings.TrimSpace(sourceURI)
	if uri == "" {
		return sdk.Fact{}, fmt.Errorf("%s observation requires source_uri", kind)
	}
	if err := checkSourceURI(uri); err != nil {
		return sdk.Fact{}, err
	}
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode %s payload: %w", kind, err)
	}
	var sharedPayload any
	if err := json.Unmarshal(encodedPayload, &sharedPayload); err != nil {
		return sdk.Fact{}, fmt.Errorf("decode %s validation payload: %w", kind, err)
	}
	if err := sdk.ValidateShareSafeKeys(sharedPayload); err != nil {
		return sdk.Fact{}, fmt.Errorf("%s payload contains unredacted sensitive key: %w", kind, err)
	}
	observedAt := boundary.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	record := strings.TrimSpace(recordID)
	if record == "" {
		record = stableKey
	}
	return sdk.Fact{
		Kind:             kind,
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
			RecordID:     record,
		},
		Payload: payload,
	}, nil
}

// specialtyContractDeclarations returns the Wave 0 specialty-kind Contract
// entries: every seamed kind at schema 1.0.0 with reported confidence. It
// lives here (not in collector.go) to keep the root file under the 500-line
// file cap; contract_manifest_test.go locks the full set.
func specialtyContractDeclarations() []sdk.FactDeclaration {
	kinds := []string{
		AWSKindDNSRecord,
		AWSKindSecurityGroupRule,
		AWSKindIAMPermission,
		AWSKindResourcePolicyPermission,
		AWSKindEC2InstancePosture,
		AWSKindRDSInstancePosture,
		AWSKindS3ExternalPrincipalGrant,
	}
	declarations := make([]sdk.FactDeclaration, 0, len(kinds))
	for _, kind := range kinds {
		declarations = append(declarations, sdk.FactDeclaration{
			Kind:             kind,
			SchemaVersions:   []string{"1.0.0"},
			SourceConfidence: []sdk.SourceConfidence{sdk.SourceConfidenceReported},
		})
	}
	return declarations
}

func specialtyStringPtr(value string) *string { return &value }

func specialtyBoolPtr(value bool) *bool { return &value }

func specialtyIntPtr(value int) *int { return &value }

// specialtyBoundaryValue carries a boundary string into the payload, trimmed
// exactly like the in-tree boundaryValue helper.
func specialtyBoundaryValue(value string) *string {
	trimmed := strings.TrimSpace(value)
	return &trimmed
}

// specialtyAnchors deduplicates correlation anchors, preserving first-seen
// order and dropping blanks, exactly like the in-tree normalizedAnchors.
func specialtyAnchors(values []string, fallback ...string) []string {
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
