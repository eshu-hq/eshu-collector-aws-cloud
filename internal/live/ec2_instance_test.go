// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestInstanceRecordRetainsLegacyIdentityObservation(t *testing.T) {
	instance := ec2types.Instance{
		InstanceId: aws.String(" i-123 "),
		ImageId:    aws.String(" ami-123 "),
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
	if missing := instanceRecord(instance, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}); missing.Resource != nil {
		t.Fatalf("instance without ID emitted typed resource = %#v", missing.Resource)
	}
}
