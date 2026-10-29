// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
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

func TestAMIOnlyResourcePreservesPlaceholderCount(t *testing.T) {
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	seen := make(map[string]struct{})
	var listed []collector.Record
	for _, instanceID := range []string{"i-111", "i-222"} {
		var err error
		listed, err = appendInstanceRecords(listed, ec2types.Instance{
			InstanceId: aws.String(instanceID), ImageId: aws.String("ami-123"),
		}, "us-east-1", identity, seen)
		if err != nil {
			t.Fatal(err)
		}
	}
	outcome, err := (Collector{
		LoadConfig:     func(_ context.Context, region string) (aws.Config, error) { return aws.Config{Region: region}, nil },
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) { return identity, nil },
		Loaders:        map[string]Loader{"ec2": func(context.Context, aws.Config, VerifiedIdentity) ([]collector.Record, error) { return listed, nil }},
	}).CollectReport(context.Background(), Config{AccountID: identity.AccountID, Regions: []string{"us-east-1"}, Services: []string{"ec2"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Report.Records) != 2 || len(outcome.Resources) != 3 || len(outcome.Relationships) != 2 {
		t.Fatalf("placeholder records=%d typed resources=%d relationships=%d, want 2/3/2", len(outcome.Report.Records), len(outcome.Resources), len(outcome.Relationships))
	}
	claim := sdk.Claim{
		ComponentID: collector.ComponentID, InstanceID: "synthetic-instance",
		CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem,
		Scope:        sdk.Scope{ID: "component:synthetic-instance", Kind: "component"},
		GenerationID: "generation-1", FencingToken: "fence-1",
	}
	uri := "aws://123456789012"
	limits := collector.ResourceUse{MaxRecordsPerClaim: 8, MaxPayloadBytes: 65536}
	base, err := collector.Collect(claim, outcome.Report, collector.CollectOptions{SourceURI: uri, ObservedAt: time.Now().UTC(), Limits: limits})
	if err != nil || len(base.Facts) != 3 || base.Facts[2].Payload["record_count"] != 2 {
		t.Fatalf("placeholder facts = %d, result = %#v, err = %v", len(base.Facts), base, err)
	}
	withResources, err := collector.AppendLiveResources(base, outcome.Resources, uri, limits)
	if err != nil || len(withResources.Facts) != 6 {
		t.Fatalf("facts after typed resources = %d, err = %v", len(withResources.Facts), err)
	}
	complete, err := collector.AppendLiveRelationships(withResources, outcome.Relationships, uri, limits)
	if err != nil || complete.State != sdk.ResultComplete || len(complete.Facts) != 8 || complete.Statuses[0].FactCount != 8 {
		t.Fatalf("final fact budget = %#v, err = %v", complete, err)
	}
	limits.MaxRecordsPerClaim = 7
	limited, err := collector.AppendLiveRelationships(withResources, outcome.Relationships, uri, limits)
	if err != nil || limited.State != sdk.ResultTerminal || len(limited.Facts) != 0 {
		t.Fatalf("seven-fact budget did not fail terminal: %#v, err = %v", limited, err)
	}
}
