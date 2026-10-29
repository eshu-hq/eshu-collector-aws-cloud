// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
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

func TestSecurityGroupAnchorsReachClaimResources(t *testing.T) {
	group := ec2types.SecurityGroup{GroupId: aws.String("sg-123"), GroupName: aws.String(" web ")}
	row := securityGroupRecord(group, "us-east-1")
	reader := Collector{
		LoadConfig: fakeConfig(&[]string{}), VerifyAccount: verifiedAccount,
		Loaders: map[string]Loader{"ec2": func(_ context.Context, _ aws.Config) ([]collector.Record, error) {
			return []collector.Record{row}, nil
		}},
	}
	outcome, err := reader.CollectReport(context.Background(), Config{
		AccountID: "055929692761", Regions: []string{"us-east-1"}, Services: []string{"ec2"},
	})
	if err != nil {
		t.Fatalf("CollectReport: %v", err)
	}
	if len(outcome.Resources) != 1 || !reflect.DeepEqual(outcome.Resources[0].CorrelationAnchors, []string{"sg-123", "web"}) {
		t.Fatalf("security group anchors = %#v", outcome.Resources)
	}
}
