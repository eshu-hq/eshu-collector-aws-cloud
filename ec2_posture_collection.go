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

// AppendLiveEC2InstancePostures adds the metadata already observed in
// DescribeInstances under the claim's fact-count and payload-size limits.
func AppendLiveEC2InstancePostures(result sdk.Result, observations []EC2InstancePostureObservation, sourceURI string, limits ResourceUse) (sdk.Result, error) {
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
		fact, err := NewEC2InstancePostureFact(observation)
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
			return sdk.Result{}, fmt.Errorf("encode EC2 instance posture payload: %w", err)
		}
		if len(encoded) > limits.MaxPayloadBytes {
			return terminalResult(result.Claim, result.Generation.ObservedAt, "payload-budget-exceeded"), nil
		}
		result.Facts = append(result.Facts, fact)
	}
	for index := range result.Statuses {
		result.Statuses[index].FactCount = len(result.Facts)
	}
	return result, nil
}

// NewEC2InstancePostureFact builds a typed, claim-bound posture fact from a
// single DescribeInstances row. The host claim supplies scope and generation.
func NewEC2InstancePostureFact(observation EC2InstancePostureObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(observation.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	if observation.Boundary.ServiceKind != "ec2" {
		return sdk.Fact{}, fmt.Errorf("EC2 posture requires ec2 service boundary")
	}
	instanceID := strings.TrimSpace(observation.InstanceID)
	arn := strings.TrimSpace(observation.ARN)
	if instanceID == "" && arn == "" {
		return sdk.Fact{}, fmt.Errorf("EC2 posture requires instance_id or arn")
	}
	if strings.TrimSpace(observation.SourceURI) == "" {
		return sdk.Fact{}, fmt.Errorf("EC2 posture requires source_uri")
	}
	if err := checkSourceURI(observation.SourceURI); err != nil {
		return sdk.Fact{}, err
	}
	identity := instanceID
	if identity == "" {
		identity = arn
	}
	keyRecord := map[string]any{"fact_type": AWSKindEC2InstancePosture, "identity": map[string]any{
		"account_id": observation.Boundary.AccountID, "instance_id": identity, "region": observation.Boundary.Region,
	}}
	encodedKey, err := json.Marshal(keyRecord)
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode EC2 posture identity: %w", err)
	}
	digest := sha256.Sum256(encodedKey)
	stableKey := hex.EncodeToString(digest[:])
	devices := make([]awsv1.BlockDevice, 0, len(observation.BlockDevices))
	for _, device := range observation.BlockDevices {
		devices = append(devices, awsv1.BlockDevice{
			DeviceName:          resourceStringPointer(strings.TrimSpace(device.DeviceName)),
			VolumeID:            resourceStringPointer(strings.TrimSpace(device.VolumeID)),
			DeleteOnTermination: postureBoolPointer(device.DeleteOnTermination),
			Status:              resourceStringPointer(strings.TrimSpace(device.Status)),
			Encrypted:           device.Encrypted,
		})
	}
	if len(devices) == 0 {
		devices = nil
	}
	payload, err := factschema.EncodeEC2InstancePosture(awsv1.EC2InstancePosture{
		AccountID: observation.Boundary.AccountID, Region: observation.Boundary.Region,
		ServiceKind:         resourceStringPointer("ec2"),
		CollectorInstanceID: resourceStringPointer(observation.Boundary.CollectorInstanceID),
		InstanceID:          resourceStringPointer(instanceID), ARN: resourceStringPointer(arn),
		ResourceType:              resourceStringPointer("aws_ec2_instance"),
		State:                     resourceStringPointer(strings.TrimSpace(observation.State)),
		IMDSv2Required:            observation.IMDSv2Required,
		IMDSHTTPEndpoint:          resourceStringPointer(strings.TrimSpace(observation.HTTPEndpoint)),
		IMDSHTTPPutHopLimit:       observation.HTTPPutResponseHopLimit,
		UserDataPresent:           observation.UserDataPresent,
		DetailedMonitoringEnabled: postureBoolPointer(observation.DetailedMonitoring),
		EBSOptimized:              postureBoolPointer(observation.EBSOptimized),
		PublicIPAssociated:        postureBoolPointer(observation.PublicIPAssociated),
		PublicIPAddress:           resourceStringPointer(strings.TrimSpace(observation.PublicIPAddress)),
		InstanceProfileARN:        resourceStringPointer(strings.TrimSpace(observation.InstanceProfileARN)),
		Tenancy:                   resourceStringPointer(strings.TrimSpace(observation.Tenancy)),
		NitroEnclaveEnabled:       postureBoolPointer(observation.NitroEnclaveEnabled),
		BlockDevices:              devices,
		CorrelationAnchors:        normalizedResourceAnchors(nil, arn, instanceID),
	})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode EC2 posture payload: %w", err)
	}
	if err := sdk.ValidateShareSafeKeys(payload); err != nil {
		return sdk.Fact{}, fmt.Errorf("EC2 posture payload contains unredacted sensitive key: %w", err)
	}
	observedAt := observation.Boundary.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	recordID := strings.TrimSpace(observation.SourceRecordID)
	if recordID == "" {
		recordID = identity
	}
	return sdk.Fact{
		Kind: AWSKindEC2InstancePosture, SchemaVersion: "1.0.0", StableKey: stableKey,
		SourceConfidence: sdk.SourceConfidenceReported, ObservedAt: observedAt,
		SourceRef: sdk.SourceRef{
			SourceSystem: SourceSystem, ScopeID: observation.Boundary.ScopeID,
			GenerationID: observation.Boundary.GenerationID, FactKey: stableKey, URI: observation.SourceURI,
			RecordID: recordID,
		},
		Payload: payload,
	}, nil
}

func postureBoolPointer(value bool) *bool { return &value }
