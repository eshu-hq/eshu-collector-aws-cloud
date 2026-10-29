// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestVolumeRecordRetainsReportedEBSMetadata(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	volume := ec2types.Volume{
		VolumeId: aws.String("vol-123"), State: ec2types.VolumeStateInUse,
		AvailabilityZone: aws.String("us-east-1a"), Encrypted: aws.Bool(true),
		Iops: aws.Int32(3000), Size: aws.Int32(64), KmsKeyId: aws.String("key-123"),
		CreateTime: &created, VolumeType: ec2types.VolumeTypeGp3,
		Tags: []ec2types.Tag{
			{Key: aws.String("environment"), Value: aws.String("qa")},
			{Key: aws.String("Name"), Value: aws.String("database volume")},
		},
		Attachments: []ec2types.VolumeAttachment{{InstanceId: aws.String("i-123"), Device: aws.String("/dev/xvda")}},
	}
	got := volumeRecord(volume, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if got.Resource == nil {
		t.Fatal("typed volume missing")
	}
	resource := got.Resource
	if resource.ARN != "arn:aws:ec2:us-east-1:123456789012:volume/vol-123" {
		t.Fatalf("volume ARN = %q", resource.ARN)
	}
	if got.Relationship == nil ||
		got.Relationship.RelationshipType != "ec2_volume_uses_kms_key" ||
		got.Relationship.SourceResourceID != "vol-123" ||
		got.Relationship.SourceARN != resource.ARN ||
		got.Relationship.TargetResourceID != "key-123" ||
		got.Relationship.TargetType != "aws_kms_key" ||
		got.Relationship.SourceRecordID != "vol-123#kms#key-123" {
		t.Fatalf("KMS relationship = %#v", got.Relationship)
	}
	if got.Name != "database volume" {
		t.Fatalf("placeholder name = %q", got.Name)
	}
	if resource.ResourceID != "vol-123" || resource.Name != "vol-123" || resource.State != "in-use" || resource.Tags["environment"] != "qa" {
		t.Fatalf("volume identity/state/tags = %+v", resource)
	}
	attrs := resource.Attributes
	if attrs["encrypted"] != true || attrs["iops"] != int32(3000) || attrs["size_gib"] != int32(64) || attrs["kms_key_id"] != "key-123" {
		t.Fatalf("volume metadata = %#v", attrs)
	}
	attachments, ok := attrs["attachments"].([]map[string]any)
	if !ok || len(attachments) != 1 || attachments[0]["instance_id"] != "i-123" {
		t.Fatalf("attachments = %#v", attrs["attachments"])
	}
	if attrs["create_time"] != created {
		t.Fatalf("create time = %#v", attrs["create_time"])
	}
}

func TestVolumeRecordUsesVerifiedPartitionAndKMSARN(t *testing.T) {
	keyARN := "arn:aws-cn:kms:cn-north-1:123456789012:key/abcd"
	volume := ec2types.Volume{
		VolumeId: aws.String("vol-123"), KmsKeyId: aws.String(keyARN),
	}
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws-cn"}
	got := volumeRecord(volume, "cn-north-1", identity)
	if got.Resource == nil || got.Resource.ARN != "arn:aws-cn:ec2:cn-north-1:123456789012:volume/vol-123" {
		t.Fatalf("volume identity = %#v", got.Resource)
	}
	if got.Relationship == nil || got.Relationship.TargetARN != keyARN {
		t.Fatalf("KMS ARN = %#v", got.Relationship)
	}
	volume.KmsKeyId = nil
	if noKey := volumeRecord(volume, "cn-north-1", identity); noKey.Relationship != nil {
		t.Fatalf("unexpected KMS link = %#v", noKey.Relationship)
	}
}
