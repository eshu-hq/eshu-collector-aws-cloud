// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"strings"

	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/factschema"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// NewEC2InstancePostureFact builds the durable ec2_instance_posture fact for
// one EC2 instance's derived security and operations posture. It requires the
// instance id (or ARN) as a join anchor and copies only IMDS settings,
// presence/derived booleans, the instance-profile ARN, and per-volume
// block-device metadata into the payload. The raw user-data string, console
// output, and any other instance payload never reach this builder.
//
// It emits no graph edges and mirrors the in-tree
// NewEC2InstancePostureEnvelope verbatim so stable keys agree on shared input.
func NewEC2InstancePostureFact(observation EC2InstancePostureObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(observation.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	arn := strings.TrimSpace(observation.ARN)
	instanceID := strings.TrimSpace(observation.InstanceID)
	if arn == "" && instanceID == "" {
		return sdk.Fact{}, fmt.Errorf("ec2 instance posture observation requires instance_id or arn")
	}
	identity := instanceID
	if identity == "" {
		identity = arn
	}
	stableKey, err := specialtyStableKey(AWSKindEC2InstancePosture, map[string]any{
		"account_id":  observation.Boundary.AccountID,
		"instance_id": identity,
		"region":      observation.Boundary.Region,
	})
	if err != nil {
		return sdk.Fact{}, err
	}
	anchors := specialtyAnchors(nil, arn, instanceID)
	payload, err := factschema.EncodeEC2InstancePosture(awsv1.EC2InstancePosture{
		AccountID:                 observation.Boundary.AccountID,
		Region:                    observation.Boundary.Region,
		ServiceKind:               specialtyBoundaryValue(observation.Boundary.ServiceKind),
		CollectorInstanceID:       specialtyBoundaryValue(observation.Boundary.CollectorInstanceID),
		ResourceType:              specialtyStringPtr(catalog.ResourceTypeEC2Instance),
		ARN:                       specialtyStringPtr(arn),
		InstanceID:                specialtyStringPtr(instanceID),
		State:                     specialtyStringPtr(strings.TrimSpace(observation.State)),
		IMDSv2Required:            observation.IMDSv2Required,
		IMDSHTTPEndpoint:          specialtyStringPtr(strings.TrimSpace(observation.HTTPEndpoint)),
		IMDSHTTPPutHopLimit:       observation.HTTPPutResponseHopLimit,
		UserDataPresent:           observation.UserDataPresent,
		DetailedMonitoringEnabled: specialtyBoolPtr(observation.DetailedMonitoring),
		EBSOptimized:              specialtyBoolPtr(observation.EBSOptimized),
		PublicIPAssociated:        specialtyBoolPtr(observation.PublicIPAssociated),
		PublicIPAddress:           specialtyStringPtr(strings.TrimSpace(observation.PublicIPAddress)),
		InstanceProfileARN:        specialtyStringPtr(strings.TrimSpace(observation.InstanceProfileARN)),
		Tenancy:                   specialtyStringPtr(strings.TrimSpace(observation.Tenancy)),
		NitroEnclaveEnabled:       specialtyBoolPtr(observation.NitroEnclaveEnabled),
		BlockDevices:              ec2PostureBlockDevices(observation.BlockDevices),
		CorrelationAnchors:        anchors,
	})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode ec2_instance_posture payload: %w", err)
	}
	recordID := strings.TrimSpace(observation.SourceRecordID)
	if recordID == "" {
		recordID = identity + "#posture"
	}
	return specialtyFact(AWSKindEC2InstancePosture, stableKey, observation.Boundary, observation.SourceURI, recordID, payload)
}

func ec2PostureBlockDevices(devices []EC2BlockDevicePosture) []awsv1.BlockDevice {
	if len(devices) == 0 {
		return nil
	}
	output := make([]awsv1.BlockDevice, 0, len(devices))
	for _, device := range devices {
		output = append(output, awsv1.BlockDevice{
			DeviceName:          specialtyStringPtr(strings.TrimSpace(device.DeviceName)),
			VolumeID:            specialtyStringPtr(strings.TrimSpace(device.VolumeID)),
			DeleteOnTermination: specialtyBoolPtr(device.DeleteOnTermination),
			Status:              specialtyStringPtr(strings.TrimSpace(device.Status)),
			Encrypted:           device.Encrypted,
		})
	}
	return output
}
