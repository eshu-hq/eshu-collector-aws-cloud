// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// volumeRecord carries the metadata returned by the boundary-wide DescribeVolumes pass.
// The volume ARN and KMS edge use the caller identity verified at the claim boundary.
func volumeRecord(volume ec2types.Volume, region string, identity VerifiedIdentity) collector.Record {
	id := strings.TrimSpace(aws.ToString(volume.VolumeId))
	result := record(id, "ec2", region, ec2Name(volume.Tags, id), "volume")
	if result.Resource == nil {
		return result
	}
	resource := result.Resource
	resource.ARN = "arn:" + identity.Partition + ":ec2:" + region + ":" + identity.AccountID + ":volume/" + id
	resource.Name = id
	resource.State = string(volume.State)
	resource.Tags = ec2Tags(volume.Tags)
	resource.Attributes = map[string]any{
		"attachments":                volumeAttachments(volume.Attachments),
		"attachment_count":           len(volume.Attachments),
		"availability_zone":          strings.TrimSpace(aws.ToString(volume.AvailabilityZone)),
		"availability_zone_id":       strings.TrimSpace(aws.ToString(volume.AvailabilityZoneId)),
		"create_time":                volumeTime(volume.CreateTime),
		"encrypted":                  volumeBool(volume.Encrypted),
		"fast_restored":              volumeBool(volume.FastRestored),
		"iops":                       volumeInt32(volume.Iops),
		"kms_key_id":                 strings.TrimSpace(aws.ToString(volume.KmsKeyId)),
		"multi_attach_enabled":       volumeBool(volume.MultiAttachEnabled),
		"outpost_arn":                strings.TrimSpace(aws.ToString(volume.OutpostArn)),
		"size_gib":                   volumeInt32(volume.Size),
		"snapshot_id":                strings.TrimSpace(aws.ToString(volume.SnapshotId)),
		"source_volume_id":           strings.TrimSpace(aws.ToString(volume.SourceVolumeId)),
		"sse_type":                   strings.TrimSpace(string(volume.SseType)),
		"throughput_mibps":           volumeInt32(volume.Throughput),
		"volume_initialization_rate": volumeInt32(volume.VolumeInitializationRate),
		"volume_type":                strings.TrimSpace(string(volume.VolumeType)),
	}
	if keyID := strings.TrimSpace(aws.ToString(volume.KmsKeyId)); keyID != "" {
		keyARN := ""
		if strings.HasPrefix(keyID, "arn:") {
			keyARN = keyID
		}
		result.Relationship = &collector.LiveRelationship{
			Region: region, ServiceKind: "ec2", RelationshipType: "ec2_volume_uses_kms_key",
			SourceResourceID: id, SourceARN: resource.ARN, TargetResourceID: keyID,
			TargetARN: keyARN, TargetType: "aws_kms_key",
			SourceRecordID: id + "#kms#" + keyID,
		}
	}
	return result
}

func volumeAttachments(input []ec2types.VolumeAttachment) []map[string]any {
	if len(input) == 0 {
		return nil
	}
	output := make([]map[string]any, 0, len(input))
	for _, attachment := range input {
		output = append(output, map[string]any{
			"associated_resource":     strings.TrimSpace(aws.ToString(attachment.AssociatedResource)),
			"attach_time":             volumeTime(attachment.AttachTime),
			"delete_on_termination":   aws.ToBool(attachment.DeleteOnTermination),
			"device":                  strings.TrimSpace(aws.ToString(attachment.Device)),
			"ebs_card_index":          volumeInt32(attachment.EbsCardIndex),
			"instance_id":             strings.TrimSpace(aws.ToString(attachment.InstanceId)),
			"instance_owning_service": strings.TrimSpace(aws.ToString(attachment.InstanceOwningService)),
			"state":                   strings.TrimSpace(string(attachment.State)),
			"volume_id":               strings.TrimSpace(aws.ToString(attachment.VolumeId)),
		})
	}
	return output
}

func volumeInt32(value *int32) any {
	if value == nil {
		return nil
	}
	return *value
}

func volumeBool(value *bool) any {
	if value == nil {
		return nil
	}
	return *value
}

func volumeTime(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return value.UTC()
}
