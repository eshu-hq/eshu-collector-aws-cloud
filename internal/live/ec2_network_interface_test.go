// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestNetworkInterfaceRecordRetainsLegacyObservation(t *testing.T) {
	attached := time.Date(2026, time.October, 1, 2, 3, 4, 0, time.UTC)
	interfaceData := ec2types.NetworkInterface{
		NetworkInterfaceId: aws.String(" eni-123 "), VpcId: aws.String(" vpc-123 "),
		SubnetId: aws.String(" subnet-123 "), OwnerId: aws.String("123456789012"),
		Status: ec2types.NetworkInterfaceStatusInUse, InterfaceType: ec2types.NetworkInterfaceTypeInterface,
		PrivateIpAddress: aws.String(" 10.0.0.5 "), SourceDestCheck: aws.Bool(true),
		TagSet:             []ec2types.Tag{{Key: aws.String("environment"), Value: aws.String("qa")}},
		Groups:             []ec2types.GroupIdentifier{{GroupId: aws.String("sg-123"), GroupName: aws.String("web")}},
		PrivateIpAddresses: []ec2types.NetworkInterfacePrivateIpAddress{{PrivateIpAddress: aws.String("10.0.0.5"), Primary: aws.Bool(true)}},
		Ipv6Addresses:      []ec2types.NetworkInterfaceIpv6Address{{Ipv6Address: aws.String(" 2001:db8::5 ")}},
		Attachment: &ec2types.NetworkInterfaceAttachment{
			AttachmentId: aws.String("eni-attach-123"), InstanceId: aws.String("i-123"), AttachTime: &attached,
			Status: ec2types.AttachmentStatusAttached, DeviceIndex: aws.Int32(0),
		},
	}
	got := networkInterfaceRecord(interfaceData, "us-gov-west-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws-us-gov"})
	if got.Resource == nil {
		t.Fatal("network interface typed resource missing")
	}
	resource := got.Resource
	if resource.ResourceID != "eni-123" || resource.Name != "eni-123" || resource.State != "in-use" || resource.Tags["environment"] != "qa" {
		t.Fatalf("network interface identity = %+v", resource)
	}
	if len(resource.CorrelationAnchors) != 1 || resource.CorrelationAnchors[0] != "eni-123" {
		t.Fatalf("network interface anchors = %v", resource.CorrelationAnchors)
	}
	attrs := resource.Attributes
	if attrs["vpc_id"] != "vpc-123" || attrs["subnet_id"] != "subnet-123" || attrs["primary_private_ip_address"] != "10.0.0.5" || attrs["source_dest_check"] != true {
		t.Fatalf("network interface attributes = %#v", attrs)
	}
	attachment, ok := attrs["attachment"].(map[string]any)
	if !ok || attachment["attached_resource_arn"] != "arn:aws-us-gov:ec2:us-gov-west-1:123456789012:instance/i-123" || attachment["attach_time"] != attached {
		t.Fatalf("network interface attachment = %#v", attrs["attachment"])
	}
	interfaceData.Attachment.InstanceOwnerId = aws.String("999999999999")
	owned := networkInterfaceRecord(interfaceData, "us-gov-west-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws-us-gov"})
	ownedAttachment := owned.Resource.Attributes["attachment"].(map[string]any)
	if ownedAttachment["attached_resource_arn"] != "arn:aws-us-gov:ec2:us-gov-west-1:999999999999:instance/i-123" {
		t.Fatalf("reported instance owner was lost: %#v", ownedAttachment)
	}
	groups, ok := attrs["security_groups"].([]map[string]string)
	if !ok || len(groups) != 1 || groups[0]["group_id"] != "sg-123" {
		t.Fatalf("network interface groups = %#v", attrs["security_groups"])
	}
	addresses, ok := attrs["private_ip_addresses"].([]map[string]any)
	if !ok || len(addresses) != 1 || addresses[0]["private_ip"] != "10.0.0.5" || addresses[0]["primary"] != true {
		t.Fatalf("network interface private IPs = %#v", attrs["private_ip_addresses"])
	}
	ipv6, ok := attrs["ipv6_addresses"].([]string)
	if !ok || len(ipv6) != 1 || ipv6[0] != "2001:db8::5" {
		t.Fatalf("network interface IPv6 addresses = %#v", attrs["ipv6_addresses"])
	}
	interfaceData.NetworkInterfaceId = nil
	if missing := networkInterfaceRecord(interfaceData, "us-gov-west-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws-us-gov"}); missing.Resource != nil {
		t.Fatalf("network interface without ID emitted typed resource = %#v", missing.Resource)
	}
}

func TestNetworkInterfaceDescribeInputIncludesManagedResources(t *testing.T) {
	input := networkInterfaceDescribeInput()
	if !aws.ToBool(input.IncludeManagedResources) || aws.ToInt32(input.MaxResults) != 1000 {
		t.Fatalf("DescribeNetworkInterfaces input excludes managed ENIs or changes page size: %+v", input)
	}
}
