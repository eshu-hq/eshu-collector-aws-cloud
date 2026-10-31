// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// instanceRecord retains the identity observation reported by the legacy EC2
// scanner from DescribeInstances. Instance posture is a separate fact kind.
func instanceRecord(instance ec2types.Instance, region string, identity VerifiedIdentity) collector.Record {
	id := strings.TrimSpace(aws.ToString(instance.InstanceId))
	result := record(id, "ec2", region, ec2Name(instance.Tags, id), "instance")
	if result.Resource == nil {
		return result
	}
	resource := result.Resource
	resource.ARN = "arn:" + identity.Partition + ":ec2:" + region + ":" + identity.AccountID + ":instance/" + id
	if instance.State != nil {
		resource.State = strings.TrimSpace(string(instance.State.Name))
	}
	// Anchor order mirrors the in-tree instance identity observation
	// (resource id first, ARN second): the seam would otherwise fall back to
	// (arn, resource_id) and emit a byte-different twin of the same fact.
	resource.CorrelationAnchors = []string{id, resource.ARN}
	resource.Attributes = map[string]any{"ami_id": strings.TrimSpace(aws.ToString(instance.ImageId))}
	if amiID := strings.TrimSpace(aws.ToString(instance.ImageId)); amiID != "" {
		result.Relationship = &collector.LiveRelationship{
			Region: region, ServiceKind: "ec2", RelationshipType: "ec2_instance_uses_ami",
			SourceResourceID: id, SourceARN: resource.ARN, TargetResourceID: amiID,
			TargetType: "aws_ec2_ami", SourceRecordID: id + "#ami#" + amiID,
		}
	}
	return result
}

// appendInstanceRecords retains the instance, its AMI edge, and one bare-ID
// AMI target per distinct image reported in this regional EC2 scan.
func appendInstanceRecords(records []collector.Record, instance ec2types.Instance, region string, identity VerifiedIdentity, seenAMIIDs map[string]struct{}) ([]collector.Record, error) {
	var err error
	row := instanceRecord(instance, region, identity)
	row.EC2Posture = instancePostureObservation(instance, region, identity)
	records, err = appendEC2Record(records, row)
	if err != nil {
		return nil, err
	}
	amiID := strings.TrimSpace(aws.ToString(instance.ImageId))
	if amiID == "" {
		return records, nil
	}
	if _, exists := seenAMIIDs[amiID]; exists {
		return records, nil
	}
	ami := record(amiID, "ec2", region, amiID, "ami")
	ami.TypedOnly = true
	records, err = appendEC2Record(records, ami)
	if err != nil {
		return nil, err
	}
	seenAMIIDs[amiID] = struct{}{}
	return records, nil
}

// instancePostureObservation maps the DescribeInstances row already fetched
// for the identity fact into the normalized ec2_instance_posture observation.
// It mirrors the in-tree instance mapper field for field: IMDS settings,
// derived booleans, the instance-profile ARN, tenancy, Nitro-enclave state,
// and per-volume block-device metadata. User-data presence stays nil
// (unknown): the presence-only contract never reads user-data content, and no
// bounded enrichment sets it on this pass. It adds no AWS API call.
func instancePostureObservation(instance ec2types.Instance, region string, identity VerifiedIdentity) *collector.EC2InstancePostureObservation {
	instanceID := strings.TrimSpace(aws.ToString(instance.InstanceId))
	arn := ""
	if instanceID != "" {
		arn = "arn:" + identity.Partition + ":ec2:" + region + ":" + identity.AccountID + ":instance/" + instanceID
	}
	state := ""
	if instance.State != nil {
		state = strings.TrimSpace(string(instance.State.Name))
	}
	sourceID := instanceID
	if sourceID == "" {
		sourceID = arn
	}
	return &collector.EC2InstancePostureObservation{
		Boundary:                collector.Boundary{Region: region, ServiceKind: "ec2"},
		ARN:                     arn,
		InstanceID:              instanceID,
		State:                   state,
		IMDSv2Required:          postureIMDSv2Required(instance.MetadataOptions),
		HTTPEndpoint:            postureIMDSHTTPEndpoint(instance.MetadataOptions),
		HTTPPutResponseHopLimit: postureIMDSHopLimit(instance.MetadataOptions),
		UserDataPresent:         nil,
		DetailedMonitoring:      postureDetailedMonitoring(instance.Monitoring),
		EBSOptimized:            aws.ToBool(instance.EbsOptimized),
		PublicIPAssociated:      strings.TrimSpace(aws.ToString(instance.PublicIpAddress)) != "",
		PublicIPAddress:         strings.TrimSpace(aws.ToString(instance.PublicIpAddress)),
		InstanceProfileARN:      postureInstanceProfileARN(instance.IamInstanceProfile),
		Tenancy:                 postureTenancy(instance.Placement),
		NitroEnclaveEnabled:     postureEnclaveEnabled(instance.EnclaveOptions),
		BlockDevices:            postureBlockDevices(instance.BlockDeviceMappings),
		SourceRecordID:          sourceID,
	}
}

func postureIMDSv2Required(options *ec2types.InstanceMetadataOptionsResponse) *bool {
	if options == nil {
		return nil
	}
	required := options.HttpTokens == ec2types.HttpTokensStateRequired
	return &required
}

func postureIMDSHTTPEndpoint(options *ec2types.InstanceMetadataOptionsResponse) string {
	if options == nil {
		return ""
	}
	return string(options.HttpEndpoint)
}

func postureIMDSHopLimit(options *ec2types.InstanceMetadataOptionsResponse) *int32 {
	if options == nil {
		return nil
	}
	return options.HttpPutResponseHopLimit
}

func postureDetailedMonitoring(monitoring *ec2types.Monitoring) bool {
	if monitoring == nil {
		return false
	}
	return monitoring.State == ec2types.MonitoringStateEnabled ||
		monitoring.State == ec2types.MonitoringStatePending
}

func postureInstanceProfileARN(profile *ec2types.IamInstanceProfile) string {
	if profile == nil {
		return ""
	}
	return strings.TrimSpace(aws.ToString(profile.Arn))
}

func postureTenancy(placement *ec2types.Placement) string {
	if placement == nil {
		return ""
	}
	return string(placement.Tenancy)
}

func postureEnclaveEnabled(options *ec2types.EnclaveOptions) bool {
	if options == nil {
		return false
	}
	return aws.ToBool(options.Enabled)
}

func postureBlockDevices(input []ec2types.InstanceBlockDeviceMapping) []collector.EC2BlockDevicePosture {
	if len(input) == 0 {
		return nil
	}
	output := make([]collector.EC2BlockDevicePosture, 0, len(input))
	for _, mapping := range input {
		device := collector.EC2BlockDevicePosture{
			DeviceName: strings.TrimSpace(aws.ToString(mapping.DeviceName)),
		}
		if mapping.Ebs != nil {
			device.VolumeID = strings.TrimSpace(aws.ToString(mapping.Ebs.VolumeId))
			device.DeleteOnTermination = aws.ToBool(mapping.Ebs.DeleteOnTermination)
			device.Status = strings.TrimSpace(string(mapping.Ebs.Status))
		}
		output = append(output, device)
	}
	return output
}
