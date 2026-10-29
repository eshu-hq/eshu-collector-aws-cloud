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
	resource.Attributes = map[string]any{"ami_id": strings.TrimSpace(aws.ToString(instance.ImageId))}
	result.EC2Posture = instancePosture(instance, resource)
	if amiID := strings.TrimSpace(aws.ToString(instance.ImageId)); amiID != "" {
		result.Relationship = &collector.LiveRelationship{
			Region: region, ServiceKind: "ec2", RelationshipType: "ec2_instance_uses_ami",
			SourceResourceID: id, SourceARN: resource.ARN, TargetResourceID: amiID,
			TargetType: "aws_ec2_ami", SourceRecordID: id + "#ami#" + amiID,
		}
	}
	return result
}

// instancePosture uses only metadata returned by DescribeInstances. In
// particular, user-data presence and EBS encryption remain unobserved.
func instancePosture(instance ec2types.Instance, resource *collector.LiveResource) *collector.EC2InstancePostureObservation {
	posture := &collector.EC2InstancePostureObservation{
		InstanceID:          resource.ResourceID,
		ARN:                 resource.ARN,
		State:               resource.State,
		DetailedMonitoring:  instance.Monitoring != nil && (instance.Monitoring.State == ec2types.MonitoringStateEnabled || instance.Monitoring.State == ec2types.MonitoringStatePending),
		EBSOptimized:        aws.ToBool(instance.EbsOptimized),
		PublicIPAssociated:  strings.TrimSpace(aws.ToString(instance.PublicIpAddress)) != "",
		PublicIPAddress:     strings.TrimSpace(aws.ToString(instance.PublicIpAddress)),
		NitroEnclaveEnabled: instance.EnclaveOptions != nil && aws.ToBool(instance.EnclaveOptions.Enabled),
		SourceRecordID:      resource.ResourceID,
	}
	if instance.MetadataOptions != nil {
		posture.IMDSv2Required = boolPointer(instance.MetadataOptions.HttpTokens == ec2types.HttpTokensStateRequired)
		posture.HTTPEndpoint = string(instance.MetadataOptions.HttpEndpoint)
		posture.HTTPPutResponseHopLimit = instance.MetadataOptions.HttpPutResponseHopLimit
	}
	if instance.IamInstanceProfile != nil {
		posture.InstanceProfileARN = aws.ToString(instance.IamInstanceProfile.Arn)
	}
	if instance.Placement != nil {
		posture.Tenancy = string(instance.Placement.Tenancy)
	}
	for _, mapping := range instance.BlockDeviceMappings {
		device := collector.EC2BlockDevicePosture{DeviceName: aws.ToString(mapping.DeviceName)}
		if mapping.Ebs != nil {
			device.VolumeID = aws.ToString(mapping.Ebs.VolumeId)
			device.DeleteOnTermination = aws.ToBool(mapping.Ebs.DeleteOnTermination)
			device.Status = string(mapping.Ebs.Status)
		}
		posture.BlockDevices = append(posture.BlockDevices, device)
	}
	return posture
}

func boolPointer(value bool) *bool { return &value }

// appendInstanceRecords retains the instance, its AMI edge, and one bare-ID
// AMI target per distinct image reported in this regional EC2 scan.
func appendInstanceRecords(records []collector.Record, instance ec2types.Instance, region string, identity VerifiedIdentity, seenAMIIDs map[string]struct{}) ([]collector.Record, error) {
	var err error
	row := instanceRecord(instance, region, identity)
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
