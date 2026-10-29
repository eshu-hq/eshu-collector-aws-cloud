// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestEC2RecordRejectsMissingTypedIdentity(t *testing.T) {
	missing := vpcRecord(ec2types.Vpc{Tags: []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("tag-name")}}}, "us-east-1")
	if _, err := appendEC2Record(nil, missing); err == nil {
		t.Fatal("missing VPC ID was accepted")
	}
	if _, err := appendEC2Record(nil, subnetRecord(ec2types.Subnet{}, "us-east-1")); err == nil {
		t.Fatal("subnet missing both ID and ARN was accepted")
	}
	subnet := subnetRecord(ec2types.Subnet{SubnetArn: aws.String("arn:aws:ec2:us-east-1:123456789012:subnet/subnet-123")}, "us-east-1")
	if records, err := appendEC2Record(nil, subnet); err != nil || len(records) != 1 {
		t.Fatalf("ARN-only subnet rejected: records=%v error=%v", records, err)
	}
}

func TestSecurityGroupRuleRecordUsesDeterministicFallback(t *testing.T) {
	rule := ec2types.SecurityGroupRule{GroupId: aws.String("sg-123"), IpProtocol: aws.String("tcp"), CidrIpv4: aws.String("10.0.0.0/8")}
	first, err := securityGroupRuleRecord(rule, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := securityGroupRuleRecord(rule, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if first.Resource == nil || !strings.HasPrefix(first.Resource.ResourceID, "security-group-rule:") || first.Resource.ResourceID != second.Resource.ResourceID {
		t.Fatalf("rule fallback = %#v / %#v", first.Resource, second.Resource)
	}
	rule.CidrIpv4 = aws.String("10.1.0.0/16")
	changed, err := securityGroupRuleRecord(rule, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if changed.Resource == nil || first.Resource.ResourceID == changed.Resource.ResourceID {
		t.Fatalf("rule fallback ignores address range: first=%#v changed=%#v", first.Resource, changed.Resource)
	}
}
