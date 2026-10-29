// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestSubnetRecordRetainsLegacyObservation(t *testing.T) {
	subnet := ec2types.Subnet{
		SubnetId: aws.String("subnet-123"), SubnetArn: aws.String("arn:aws:ec2:us-east-1:123456789012:subnet/subnet-123"),
		VpcId: aws.String("vpc-123"), OwnerId: aws.String("123456789012"),
		CidrBlock: aws.String("10.0.1.0/24"), AvailabilityZone: aws.String("us-east-1a"),
		AvailableIpAddressCount: aws.Int32(241), DefaultForAz: aws.Bool(true),
		Tags: []ec2types.Tag{{Key: aws.String("environment"), Value: aws.String("qa")}},
		Ipv6CidrBlockAssociationSet: []ec2types.SubnetIpv6CidrBlockAssociation{{
			AssociationId: aws.String("subnet-cidr-assoc-123"), Ipv6CidrBlock: aws.String("2001:db8::/64"),
		}},
	}
	got := subnetRecord(subnet, "us-east-1")
	if got.Resource == nil {
		t.Fatal("subnet typed resource missing")
	}
	if got.Relationship == nil || got.Relationship.SourceResourceID != "subnet-123" || got.Relationship.TargetResourceID != "vpc-123" || got.Relationship.RelationshipType != "ec2_subnet_in_vpc" {
		t.Fatalf("subnet VPC relationship = %#v", got.Relationship)
	}
	resource := got.Resource
	if resource.ResourceID != "subnet-123" || resource.ARN != aws.ToString(subnet.SubnetArn) || resource.Name != "subnet-123" || resource.Tags["environment"] != "qa" {
		t.Fatalf("subnet identity = %+v", resource)
	}
	if resource.Attributes["vpc_id"] != "vpc-123" || resource.Attributes["availability_zone"] != "us-east-1a" || resource.Attributes["available_ip_address_count"] != int32(241) || resource.Attributes["default_for_az"] != true {
		t.Fatalf("subnet attributes = %#v", resource.Attributes)
	}
	associations, ok := resource.Attributes["ipv6_cidr_block_associations"].([]map[string]any)
	if !ok || len(associations) != 1 || associations[0]["association_id"] != "subnet-cidr-assoc-123" {
		t.Fatalf("subnet IPv6 associations = %#v", resource.Attributes["ipv6_cidr_block_associations"])
	}
	subnet.SubnetId = nil
	fallback := subnetRecord(subnet, "us-east-1")
	if fallback.Relationship != nil {
		t.Fatalf("ARN-only subnet acquired a VPC relationship: %#v", fallback.Relationship)
	}
	if fallback.Resource == nil || fallback.Resource.ResourceID != aws.ToString(subnet.SubnetArn) || fallback.Resource.Name != "" {
		t.Fatalf("subnet ARN fallback = %#v", fallback.Resource)
	}
	subnet.SubnetArn = nil
	if missing := subnetRecord(subnet, "us-east-1"); missing.Resource != nil {
		t.Fatalf("subnet without identity emitted typed resource = %#v", missing.Resource)
	}
}
