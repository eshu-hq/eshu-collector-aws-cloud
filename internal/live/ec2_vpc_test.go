// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"testing"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestVPCRecordRetainsLegacyObservation(t *testing.T) {
	vpc := ec2types.Vpc{
		VpcId:         aws.String("vpc-123"),
		OwnerId:       aws.String("123456789012"),
		CidrBlock:     aws.String("10.0.0.0/16"),
		DhcpOptionsId: aws.String("dopt-123"),
		IsDefault:     aws.Bool(true),
		State:         ec2types.VpcStateAvailable,
		Tags:          []ec2types.Tag{{Key: aws.String("environment"), Value: aws.String("qa")}},
		CidrBlockAssociationSet: []ec2types.VpcCidrBlockAssociation{{
			AssociationId: aws.String("vpc-cidr-assoc-123"), CidrBlock: aws.String("10.0.0.0/16"),
		}},
	}
	got := vpcRecord(vpc, "us-east-1")
	if got.Resource == nil {
		t.Fatal("VPC typed resource missing")
	}
	resource := got.Resource
	if resource.ResourceID != "vpc-123" || resource.Name != "vpc-123" || resource.State != "available" || resource.Tags["environment"] != "qa" {
		t.Fatalf("VPC identity/tags = %+v", resource)
	}
	if resource.Attributes["cidr_block"] != "10.0.0.0/16" || resource.Attributes["owner_id"] != "123456789012" || resource.Attributes["is_default"] != true {
		t.Fatalf("VPC attributes = %#v", resource.Attributes)
	}
	associations, ok := resource.Attributes["ipv4_cidr_block_associations"].([]map[string]any)
	if !ok || len(associations) != 1 || associations[0]["association_id"] != "vpc-cidr-assoc-123" {
		t.Fatalf("VPC CIDR associations = %#v", resource.Attributes["ipv4_cidr_block_associations"])
	}
	outcome, err := (Collector{
		LoadConfig: func(_ context.Context, region string) (aws.Config, error) {
			return aws.Config{Region: region}, nil
		},
		VerifyAccount: func(context.Context, aws.Config) (string, error) { return "123456789012", nil },
		Loaders: map[string]Loader{
			"ec2": func(context.Context, aws.Config) ([]collector.Record, error) {
				return []collector.Record{got}, nil
			},
		},
	}).CollectReport(context.Background(), Config{
		AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"ec2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Resources) != 1 || outcome.Resources[0].Attributes["cidr_block"] != "10.0.0.0/16" || outcome.Resources[0].Tags["environment"] != "qa" {
		t.Fatalf("claim-bound VPC resources = %#v", outcome.Resources)
	}
}
