// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
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

func TestSecurityGroupRuleRecordRetainsLegacyObservation(t *testing.T) {
	rule := ec2types.SecurityGroupRule{
		SecurityGroupRuleId: aws.String(" sgr-123 "), GroupId: aws.String(" sg-123 "),
		GroupOwnerId: aws.String("123456789012"), IsEgress: aws.Bool(true),
		IpProtocol: aws.String(" tcp "), FromPort: aws.Int32(443), ToPort: aws.Int32(443),
		CidrIpv4: aws.String(" 10.0.0.0/8 "), Description: aws.String(" HTTPS "),
		Tags: []ec2types.Tag{{Key: aws.String("environment"), Value: aws.String("qa")}},
		ReferencedGroupInfo: &ec2types.ReferencedSecurityGroup{
			GroupId: aws.String(" sg-peer "), UserId: aws.String("999999999999"),
		},
	}
	got, err := securityGroupRuleRecord(rule, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Resource == nil {
		t.Fatal("security group rule typed resource missing")
	}
	resource := got.Resource
	if resource.ResourceID != "sgr-123" || resource.Name != "sgr-123" || resource.ARN != "" || resource.Tags["environment"] != "qa" {
		t.Fatalf("rule identity = %+v", resource)
	}
	if len(resource.CorrelationAnchors) != 2 || resource.CorrelationAnchors[0] != "sgr-123" || resource.CorrelationAnchors[1] != "sg-123" {
		t.Fatalf("rule anchors = %v", resource.CorrelationAnchors)
	}
	attributes := resource.Attributes
	if attributes["direction"] != "egress" || attributes["from_port"] != int32(443) || attributes["ip_protocol"] != "tcp" || attributes["cidr_ipv4"] != "10.0.0.0/8" || attributes["description"] != "HTTPS" {
		t.Fatalf("rule attributes = %#v", attributes)
	}
	referenced, ok := attributes["referenced_group"].(map[string]any)
	if !ok || referenced["group_id"] != "sg-peer" || referenced["user_id"] != "999999999999" {
		t.Fatalf("referenced group = %#v", attributes["referenced_group"])
	}
	outcome, err := (Collector{
		LoadConfig: func(_ context.Context, region string) (aws.Config, error) {
			return aws.Config{Region: region}, nil
		},
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{
			"ec2": func(context.Context, aws.Config, VerifiedIdentity) ([]collector.Record, error) {
				return []collector.Record{got}, nil
			},
		},
	}).CollectReport(context.Background(), Config{
		AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"ec2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Resources) != 1 || len(outcome.Resources[0].CorrelationAnchors) != 2 || outcome.Resources[0].CorrelationAnchors[1] != "sg-123" {
		t.Fatalf("claim-bound rule anchors = %#v", outcome.Resources)
	}
}
