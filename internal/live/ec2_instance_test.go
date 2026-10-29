// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

func TestInstanceRecordRetainsLegacyIdentityObservation(t *testing.T) {
	instance := ec2types.Instance{
		InstanceId: aws.String(" i-123 "),
		ImageId:    aws.String(" ami-123 "),
		VpcId:      aws.String("vpc-123"),
		SubnetId:   aws.String("subnet-123"),
		State:      &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		Tags:       []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("display name")}},
	}
	got := instanceRecord(instance, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if got.Resource == nil {
		t.Fatal("instance typed resource missing")
	}
	resource := got.Resource
	if resource.ResourceID != "i-123" || resource.Name != "i-123" || resource.State != "running" || resource.ARN != "arn:aws:ec2:us-east-1:123456789012:instance/i-123" {
		t.Fatalf("instance identity = %+v", resource)
	}
	if resource.Attributes["ami_id"] != "ami-123" || len(resource.Attributes) != 1 {
		t.Fatalf("instance identity attributes = %#v", resource.Attributes)
	}
	if edge := got.Relationship; edge == nil || edge.RelationshipType != "ec2_instance_uses_ami" ||
		edge.SourceResourceID != "i-123" || edge.SourceARN != resource.ARN ||
		edge.TargetResourceID != "ami-123" || edge.TargetType != "aws_ec2_ami" ||
		edge.SourceRecordID != "i-123#ami#ami-123" {
		t.Fatalf("instance AMI relationship = %#v", edge)
	}
	for _, tc := range []struct{ region, partition, want string }{
		{"us-gov-west-1", "aws-us-gov", "arn:aws-us-gov:ec2:us-gov-west-1:123456789012:instance/i-123"},
		{"cn-north-1", "aws-cn", "arn:aws-cn:ec2:cn-north-1:123456789012:instance/i-123"},
	} {
		got := instanceRecord(instance, tc.region, VerifiedIdentity{AccountID: "123456789012", Partition: tc.partition})
		if got.Resource == nil || got.Resource.ARN != tc.want {
			t.Errorf("%s ARN = %#v, want %q", tc.region, got.Resource, tc.want)
		}
	}
	instance.InstanceId = nil
	if missing := instanceRecord(instance, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}); missing.Resource != nil || missing.Relationship != nil {
		t.Fatalf("instance without ID emitted typed facts = %#v", missing)
	}
	instance.InstanceId = aws.String("i-123")
	instance.ImageId = nil
	if noAMI := instanceRecord(instance, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}); noAMI.Relationship != nil {
		t.Fatalf("instance without AMI emitted relationship = %#v", noAMI.Relationship)
	}
}

func TestAppendInstanceRecordsDeduplicatesAMIIdentity(t *testing.T) {
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	seen := make(map[string]struct{})
	var records []collector.Record
	for _, instanceID := range []string{"i-111", "i-222"} {
		var err error
		records, err = appendInstanceRecords(records, ec2types.Instance{
			InstanceId: aws.String(instanceID), ImageId: aws.String(" ami-123 "),
		}, "us-east-1", identity, seen)
		if err != nil {
			t.Fatalf("append instance %s: %v", instanceID, err)
		}
	}
	if len(records) != 3 || records[0].Relationship == nil || records[2].Relationship == nil {
		t.Fatalf("instance and AMI records = %#v, want two edges and one target", records)
	}
	ami := records[1].Resource
	if ami == nil || ami.ResourceID != "ami-123" || ami.ResourceType != "aws_ec2_ami" || ami.Name != "ami-123" || ami.ARN != "" {
		t.Fatalf("AMI target resource = %#v", ami)
	}
	if _, err := appendInstanceRecords(records, ec2types.Instance{ImageId: aws.String("ami-456")}, "us-east-1", identity, seen); err == nil {
		t.Fatal("missing instance ID accepted")
	}
}
