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

// SSM host inventory fact kinds (eshu-hq/eshu#9557, typed contracts
// eshu-hq/eshu#9556, accepted record #9302). These are observations, not
// package findings: no vulnerability verdict, no supply-chain impact, no
// PURL, and no image digest. Field spelling mirrors the #9556 contracts
// exactly; reconcile against sdk/go/factschema/aws/v1 when the collector
// SDK release ships those kinds (then these builders encode through it).
const (
	// AWSKindSSMHostApplication is one allowlisted AWS:Application row for
	// one EC2 managed node in one dated capture.
	AWSKindSSMHostApplication = "aws_ssm_host_application"
	// AWSKindSSMHostPlatform is the platform observation for one EC2
	// managed node, with inventory or DescribeInstanceInformation
	// provenance.
	AWSKindSSMHostPlatform = "aws_ssm_host_platform"
)

const (
	// SSMHostInventoryTypeApplication is the only inventory source type
	// this collector admits for application observations.
	SSMHostInventoryTypeApplication = "AWS:Application"
	// SSMHostEC2ResourceType is the required observed resource type: the
	// EC2 instance type. Non-EC2 identities are excluded from these kinds.
	SSMHostEC2ResourceType = "AWS::EC2::Instance"
	// SSMHostPlatformSourceInventory names inventory-sourced platform
	// evidence, which carries the inventory capture time.
	SSMHostPlatformSourceInventory = "ssm_inventory"
	// SSMHostPlatformSourceDescribeInstanceInformation names platform
	// evidence from DescribeInstanceInformation, which has no inventory
	// capture time: the collector must never invent one for it.
	SSMHostPlatformSourceDescribeInstanceInformation = "describe_instance_information"
)

// SSMHostApplicationObservation is one allowlisted AWS:Application row for
// one EC2 managed node in one dated capture. Only the six allowlisted row
// fields travel: URL, Summary, hostnames, and IP addresses are excluded
// even though the API returns them.
type SSMHostApplicationObservation struct {
	Boundary       Boundary
	Partition      string
	AccountID      string
	Region         string
	InstanceID     string
	ResourceType   string
	SourceType     string
	SchemaVersion  string
	CaptureTime    string
	Name           *string
	Version        *string
	Release        *string
	Epoch          *string
	PackageID      *string
	Architecture   *string
	SourceURI      string
	SourceRecordID string
}

// SSMHostPlatformObservation is the platform observation for one EC2
// managed node: platform fields when present, the evidence provenance, and
// the observation or capture time with that provenance.
type SSMHostPlatformObservation struct {
	Boundary        Boundary
	Partition       string
	AccountID       string
	Region          string
	InstanceID      string
	ResourceType    string
	PlatformType    *string
	PlatformName    *string
	PlatformVersion *string
	SourceType      string
	// CaptureTime is set only for inventory-sourced evidence. A value
	// with DescribeInstanceInformation provenance is rejected.
	CaptureTime *string
	// ObservationTime is when this evidence was observed (RFC 3339).
	ObservationTime string
	SourceURI       string
	SourceRecordID  string
}

// ssmHostApplicationCanonicalRow is the fixed-order canonical encoding of
// exactly the six allowlisted row fields, in #9556 struct order. Nil
// decodes to "" so absent and present-but-empty hash identically.
type ssmHostApplicationCanonicalRow struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Release      string `json:"release"`
	Epoch        string `json:"epoch"`
	PackageID    string `json:"package_id"`
	Architecture string `json:"architecture"`
}

// derefSSMObservationString trims: the stable key must hash the same
// identity the payload carries, and the payload trims every value it
// admits. Untrimmed key material would give whitespace variants different
// keys with identical payloads.
func derefSSMObservationString(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

// SSMHostApplicationRowHash returns the hex SHA-256 of the canonical
// allowlisted row: the row-identity third of the stable key. Hashing is
// for identity, not a claim that the row is an OS package.
func SSMHostApplicationRowHash(obs SSMHostApplicationObservation) string {
	raw, err := json.Marshal(ssmHostApplicationCanonicalRow{
		Name:         derefSSMObservationString(obs.Name),
		Version:      derefSSMObservationString(obs.Version),
		Release:      derefSSMObservationString(obs.Release),
		Epoch:        derefSSMObservationString(obs.Epoch),
		PackageID:    derefSSMObservationString(obs.PackageID),
		Architecture: derefSSMObservationString(obs.Architecture),
	})
	if err != nil {
		panic(fmt.Sprintf("ssm host inventory: marshal canonical application row: %v", err))
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// SSMHostApplicationStableKey returns the stable key for one application
// observation: host tuple plus capture time plus the canonical row hash.
// Identical rows in a capture deduplicate on this key; another capture is
// a new observation because the capture time differs.
func SSMHostApplicationStableKey(obs SSMHostApplicationObservation) string {
	return strings.Join([]string{
		AWSKindSSMHostApplication,
		strings.TrimSpace(obs.Partition),
		strings.TrimSpace(obs.AccountID),
		strings.TrimSpace(obs.Region),
		strings.TrimSpace(obs.InstanceID),
		strings.TrimSpace(obs.CaptureTime),
		SSMHostApplicationRowHash(obs),
	}, "/")
}

// SSMHostPlatformStableKey returns the stable key for one platform
// observation: host tuple plus source type. A complete newer generation
// updates the platform observation on this key.
func SSMHostPlatformStableKey(obs SSMHostPlatformObservation) string {
	return strings.Join([]string{
		AWSKindSSMHostPlatform,
		strings.TrimSpace(obs.Partition),
		strings.TrimSpace(obs.AccountID),
		strings.TrimSpace(obs.Region),
		strings.TrimSpace(obs.InstanceID),
		strings.TrimSpace(obs.SourceType),
	}, "/")
}

func validateSSMHostTuple(partition, accountID, region, instanceID, resourceType string) error {
	for _, required := range []struct{ name, value string }{
		{"partition", partition},
		{"account_id", accountID},
		{"region", region},
		{"instance_id", instanceID},
	} {
		if strings.TrimSpace(required.value) == "" {
			return fmt.Errorf("ssm host observation requires %s", required.name)
		}
	}
	if strings.TrimSpace(resourceType) != SSMHostEC2ResourceType {
		return fmt.Errorf("ssm host observation requires resource type %q", SSMHostEC2ResourceType)
	}
	return nil
}

func ssmOptionalField(value *string) (string, bool) {
	if value == nil {
		return "", false
	}
	return strings.TrimSpace(*value), true
}

// NewSSMHostApplicationFact builds one typed aws_ssm_host_application fact.
// A missing or invalid capture time emits no fact; non-application source
// types and non-EC2 identities are rejected, never silently admitted.
func NewSSMHostApplicationFact(obs SSMHostApplicationObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(obs.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	if err := validateSSMHostTuple(obs.Partition, obs.AccountID, obs.Region, obs.InstanceID, obs.ResourceType); err != nil {
		return sdk.Fact{}, err
	}
	if strings.TrimSpace(obs.SourceType) != SSMHostInventoryTypeApplication {
		return sdk.Fact{}, fmt.Errorf("ssm host application requires source type %q", SSMHostInventoryTypeApplication)
	}
	if strings.TrimSpace(obs.SchemaVersion) == "" {
		return sdk.Fact{}, fmt.Errorf("ssm host application requires schema_version")
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(obs.CaptureTime)); err != nil {
		return sdk.Fact{}, fmt.Errorf("ssm host application requires a valid capture_time")
	}
	uri := strings.TrimSpace(obs.SourceURI)
	if uri == "" {
		return sdk.Fact{}, fmt.Errorf("ssm host application requires source_uri")
	}
	if err := checkSourceURI(uri); err != nil {
		return sdk.Fact{}, err
	}
	payload := map[string]any{
		"partition":             strings.TrimSpace(obs.Partition),
		"account_id":            strings.TrimSpace(obs.AccountID),
		"region":                strings.TrimSpace(obs.Region),
		"instance_id":           strings.TrimSpace(obs.InstanceID),
		"resource_type":         strings.TrimSpace(obs.ResourceType),
		"source_type":           strings.TrimSpace(obs.SourceType),
		"schema_version":        strings.TrimSpace(obs.SchemaVersion),
		"capture_time":          strings.TrimSpace(obs.CaptureTime),
		"collector_instance_id": strings.TrimSpace(obs.Boundary.CollectorInstanceID),
	}
	for key, value := range map[string]*string{
		"name": obs.Name, "version": obs.Version, "release": obs.Release,
		"epoch": obs.Epoch, "package_id": obs.PackageID, "architecture": obs.Architecture,
	} {
		if text, ok := ssmOptionalField(value); ok {
			payload[key] = text
		}
	}
	if err := sdk.ValidateShareSafeKeys(payload); err != nil {
		return sdk.Fact{}, fmt.Errorf("ssm host application payload contains sensitive key: %w", err)
	}
	stableKey := SSMHostApplicationStableKey(obs)
	observedAt := obs.Boundary.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	recordID := strings.TrimSpace(obs.SourceRecordID)
	if recordID == "" {
		recordID = strings.TrimSpace(obs.InstanceID) + "#application#" + stableKey[len(stableKey)-12:]
	}
	return sdk.Fact{
		Kind: AWSKindSSMHostApplication, SchemaVersion: "1.0.0", StableKey: stableKey,
		SourceConfidence: sdk.SourceConfidenceReported, ObservedAt: observedAt,
		SourceRef: sdk.SourceRef{
			SourceSystem: SourceSystem, ScopeID: obs.Boundary.ScopeID,
			GenerationID: obs.Boundary.GenerationID, FactKey: stableKey, URI: uri, RecordID: recordID,
		},
		Payload: payload,
	}, nil
}

// ValidateSSMHostPlatformProvenance rejects a platform observation whose
// provenance and capture-time pairing is incoherent in either direction: a
// DescribeInstanceInformation observation carries no inventory capture time,
// so a value here with that provenance is a contract violation; and an
// inventory observation without one has no dated capture to supersede on,
// so it is rejected here instead of failing later in fact building. This is
// deliberately stricter than ValidateSSMHostPlatformProvenance in the #9556
// contracts, which rejects only the DescribeInstanceInformation direction.
// The emitter calls it before building platform facts. hasCaptureTime
// reports whether the observation carries any capture-time value.
func ValidateSSMHostPlatformProvenance(sourceType string, hasCaptureTime bool) error {
	sourceType = strings.TrimSpace(sourceType)
	if sourceType == SSMHostPlatformSourceDescribeInstanceInformation && hasCaptureTime {
		return fmt.Errorf("ssm host inventory: capture time with DescribeInstanceInformation provenance")
	}
	if sourceType == SSMHostPlatformSourceInventory && !hasCaptureTime {
		return fmt.Errorf("ssm host inventory: inventory provenance without capture time")
	}
	return nil
}

// NewSSMHostPlatformFact builds one typed aws_ssm_host_platform fact.
// Inventory-sourced evidence requires the capture time;
// DescribeInstanceInformation evidence must not carry one.
func NewSSMHostPlatformFact(obs SSMHostPlatformObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(obs.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	if err := validateSSMHostTuple(obs.Partition, obs.AccountID, obs.Region, obs.InstanceID, obs.ResourceType); err != nil {
		return sdk.Fact{}, err
	}
	if err := ValidateSSMHostPlatformProvenance(strings.TrimSpace(obs.SourceType), obs.CaptureTime != nil); err != nil {
		return sdk.Fact{}, err
	}
	source := strings.TrimSpace(obs.SourceType)
	switch source {
	case SSMHostPlatformSourceInventory:
		if obs.CaptureTime == nil {
			return sdk.Fact{}, fmt.Errorf("ssm host platform from inventory requires capture_time")
		}
		if _, err := time.Parse(time.RFC3339, strings.TrimSpace(*obs.CaptureTime)); err != nil {
			return sdk.Fact{}, fmt.Errorf("ssm host platform requires a valid capture_time")
		}
	case SSMHostPlatformSourceDescribeInstanceInformation:
		if obs.CaptureTime != nil {
			return sdk.Fact{}, fmt.Errorf("ssm host platform from describe_instance_information must not carry capture_time")
		}
	default:
		return sdk.Fact{}, fmt.Errorf("ssm host platform requires a known source_type")
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(obs.ObservationTime)); err != nil {
		return sdk.Fact{}, fmt.Errorf("ssm host platform requires a valid observation_time")
	}
	uri := strings.TrimSpace(obs.SourceURI)
	if uri == "" {
		return sdk.Fact{}, fmt.Errorf("ssm host platform requires source_uri")
	}
	if err := checkSourceURI(uri); err != nil {
		return sdk.Fact{}, err
	}
	payload := map[string]any{
		"partition":             strings.TrimSpace(obs.Partition),
		"account_id":            strings.TrimSpace(obs.AccountID),
		"region":                strings.TrimSpace(obs.Region),
		"instance_id":           strings.TrimSpace(obs.InstanceID),
		"resource_type":         strings.TrimSpace(obs.ResourceType),
		"source_type":           source,
		"observation_time":      strings.TrimSpace(obs.ObservationTime),
		"collector_instance_id": strings.TrimSpace(obs.Boundary.CollectorInstanceID),
	}
	if obs.CaptureTime != nil {
		payload["capture_time"] = strings.TrimSpace(*obs.CaptureTime)
	}
	for key, value := range map[string]*string{
		"platform_type": obs.PlatformType, "platform_name": obs.PlatformName, "platform_version": obs.PlatformVersion,
	} {
		if text, ok := ssmOptionalField(value); ok {
			payload[key] = text
		}
	}
	if err := sdk.ValidateShareSafeKeys(payload); err != nil {
		return sdk.Fact{}, fmt.Errorf("ssm host platform payload contains sensitive key: %w", err)
	}
	stableKey := SSMHostPlatformStableKey(obs)
	observedAt := obs.Boundary.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	recordID := strings.TrimSpace(obs.SourceRecordID)
	if recordID == "" {
		recordID = strings.TrimSpace(obs.InstanceID) + "#platform#" + source
	}
	return sdk.Fact{
		Kind: AWSKindSSMHostPlatform, SchemaVersion: "1.0.0", StableKey: stableKey,
		SourceConfidence: sdk.SourceConfidenceReported, ObservedAt: observedAt,
		SourceRef: sdk.SourceRef{
			SourceSystem: SourceSystem, ScopeID: obs.Boundary.ScopeID,
			GenerationID: obs.Boundary.GenerationID, FactKey: stableKey, URI: uri, RecordID: recordID,
		},
		Payload: payload,
	}, nil
}

// AppendLiveSSMHostApplications adds claim-bound application observations
// under fact budgets. Identical rows deduplicate on the stable key.
func AppendLiveSSMHostApplications(result sdk.Result, observations []SSMHostApplicationObservation, sourceURI string, limits ResourceUse) (sdk.Result, error) {
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
		fact, err := NewSSMHostApplicationFact(observation)
		if err != nil {
			return sdk.Result{}, err
		}
		updated, capped, err := appendSSMFact(result, fact, seen, limits)
		if err != nil {
			return sdk.Result{}, err
		}
		if capped {
			return updated, nil
		}
		result = updated
	}
	for index := range result.Statuses {
		result.Statuses[index].FactCount = len(result.Facts)
	}
	return result, nil
}

// AppendLiveSSMHostPlatforms adds claim-bound platform observations under
// fact budgets. A complete newer generation updates the platform
// observation on its stable key.
func AppendLiveSSMHostPlatforms(result sdk.Result, observations []SSMHostPlatformObservation, sourceURI string, limits ResourceUse) (sdk.Result, error) {
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
		fact, err := NewSSMHostPlatformFact(observation)
		if err != nil {
			return sdk.Result{}, err
		}
		advanced, capped, err := appendSSMFact(result, fact, seen, limits)
		if err != nil {
			return sdk.Result{}, err
		}
		if capped {
			return advanced, nil
		}
		result = advanced
	}
	for index := range result.Statuses {
		result.Statuses[index].FactCount = len(result.Facts)
	}
	return result, nil
}

// appendSSMFact dedupes one fact by kind and stable key and enforces the
// record and payload budgets. It returns the updated result and true when a
// budget breach terminates the claim with a terminal result.
func appendSSMFact(result sdk.Result, fact sdk.Fact, seen map[string]struct{}, limits ResourceUse) (sdk.Result, bool, error) {
	key := fact.Kind + "\x00" + fact.StableKey
	if _, exists := seen[key]; exists {
		return result, false, nil
	}
	seen[key] = struct{}{}
	if len(result.Facts) >= limits.MaxRecordsPerClaim {
		return terminalResult(result.Claim, result.Generation.ObservedAt, "record-budget-exceeded"), true, nil
	}
	encoded, err := json.Marshal(fact.Payload)
	if err != nil {
		return sdk.Result{}, false, fmt.Errorf("encode ssm host payload: %w", err)
	}
	if len(encoded) > limits.MaxPayloadBytes {
		return terminalResult(result.Claim, result.Generation.ObservedAt, "payload-budget-exceeded"), true, nil
	}
	result.Facts = append(result.Facts, fact)
	return result, false, nil
}
