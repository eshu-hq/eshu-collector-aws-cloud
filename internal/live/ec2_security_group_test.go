// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestSecurityGroupRecordRetainsLegacyObservation(t *testing.T) {
	group := ec2types.SecurityGroup{
		GroupId: aws.String("sg-123"), GroupName: aws.String("web"),
		Description: aws.String("web traffic"), OwnerId: aws.String("123456789012"),
		VpcId: aws.String("vpc-123"),
		Tags:  []ec2types.Tag{{Key: aws.String("environment"), Value: aws.String("qa")}},
	}
	got := securityGroupRecord(group, "us-east-1")
	if got.Resource == nil {
		t.Fatal("typed security group missing")
	}
	resource := got.Resource
	if resource.ResourceID != "sg-123" || resource.Name != "web" || resource.Tags["environment"] != "qa" {
		t.Fatalf("security group identity = %+v", resource)
	}
	if resource.Attributes["description"] != "web traffic" || resource.Attributes["owner_id"] != "123456789012" || resource.Attributes["vpc_id"] != "vpc-123" {
		t.Fatalf("security group attributes = %#v", resource.Attributes)
	}
	if got.Name != "web" {
		t.Fatalf("placeholder name = %q", got.Name)
	}
}
