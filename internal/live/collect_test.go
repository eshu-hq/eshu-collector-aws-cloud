// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

func fakeConfig(regions *[]string) func(context.Context, string) (aws.Config, error) {
	return func(_ context.Context, region string) (aws.Config, error) {
		*regions = append(*regions, region)
		return aws.Config{Region: region}, nil
	}
}

func verifiedIdentity(_ context.Context, _ aws.Config) (VerifiedIdentity, error) {
	return VerifiedIdentity{AccountID: "055929692761", Partition: "aws"}, nil
}

// TestCollectReportListsOnlyAllowlistedServices proves the orchestrator calls
// exactly the configured service-region pairs: nothing outside the host
// allowlists is ever read.
func TestCollectReportListsOnlyAllowlistedServices(t *testing.T) {
	t.Parallel()

	var regions []string
	calls := map[string]int{}
	collector := Collector{
		LoadConfig:     fakeConfig(&regions),
		VerifyIdentity: verifiedIdentity,
		Loaders: map[string]Loader{
			"iam": func(_ context.Context, cfg aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
				calls["iam/"+cfg.Region]++
				return []collector.Record{{ID: "arn:role", Name: "role", Detail: "d"}}, nil
			},
			"sqs": func(_ context.Context, cfg aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
				calls["sqs/"+cfg.Region]++
				return []collector.Record{{ID: "url", Name: "queue", Detail: "d"}}, nil
			},
		},
	}
	config := Config{AccountID: "055929692761", Regions: []string{"us-east-1"}, Services: []string{"iam", "sqs"}}
	outcome, err := collector.CollectReport(context.Background(), config)
	if err != nil {
		t.Fatalf("CollectReport error = %v", err)
	}
	if len(outcome.Warnings) != 0 {
		t.Fatalf("Warnings = %v, want none", outcome.Warnings)
	}
	if len(outcome.Report.Records) != 2 {
		t.Fatalf("len(Records) = %d, want 2", len(outcome.Report.Records))
	}
	if len(calls) != 2 || !strings.Contains(outcome.Report.Source, "055929692761") {
		t.Fatalf("calls = %v source = %q, want scoped reads", calls, outcome.Report.Source)
	}
}

// TestCollectReportSkipsGlobalServicesAfterFirstRegion proves account-global
// APIs are listed once even when several regions are configured.
func TestCollectReportSkipsGlobalServicesAfterFirstRegion(t *testing.T) {
	t.Parallel()

	calls := 0
	collector := Collector{
		LoadConfig:     fakeConfig(&[]string{}),
		VerifyIdentity: verifiedIdentity,
		Loaders: map[string]Loader{
			"iam": func(_ context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
				calls++
				return []collector.Record{{ID: "arn:role", Name: "role"}}, nil
			},
		},
	}
	config := Config{AccountID: "055929692761", Regions: []string{"us-east-1", "eu-west-1"}, Services: []string{"iam"}}
	if _, err := collector.CollectReport(context.Background(), config); err != nil {
		t.Fatalf("CollectReport error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("iam calls = %d across two regions, want 1", calls)
	}
}

// TestCollectReportDegradesPartialServiceFailure proves one denied API does
// not wipe the evidence the other services returned: records commit with a
// recorded warning.
func TestCollectReportDegradesPartialServiceFailure(t *testing.T) {
	t.Parallel()

	collector := Collector{
		LoadConfig:     fakeConfig(&[]string{}),
		VerifyIdentity: verifiedIdentity,
		Loaders: map[string]Loader{
			"iam": func(_ context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
				return []collector.Record{{ID: "arn:role", Name: "role"}}, nil
			},
			"sqs": func(_ context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
				return nil, errors.New("AccessDenied: GetAttribution is denied")
			},
		},
	}
	config := Config{AccountID: "055929692761", Regions: []string{"us-east-1"}, Services: []string{"iam", "sqs"}}
	outcome, err := collector.CollectReport(context.Background(), config)
	if err != nil {
		t.Fatalf("CollectReport error = %v, want degraded outcome", err)
	}
	if len(outcome.Report.Records) != 1 {
		t.Fatalf("len(Records) = %d, want 1 surviving record", len(outcome.Report.Records))
	}
	if len(outcome.Warnings) != 1 || !strings.Contains(outcome.Warnings[0], "sqs/us-east-1") {
		t.Fatalf("Warnings = %v, want the sqs failure", outcome.Warnings)
	}
}

// TestCollectReportFailsWhenNothingIsReadable proves a total read failure
// errors instead of emitting an empty report that would retire good
// evidence as current.
func TestCollectReportFailsWhenNothingIsReadable(t *testing.T) {
	t.Parallel()

	collector := Collector{
		LoadConfig:     fakeConfig(&[]string{}),
		VerifyIdentity: verifiedIdentity,
		Loaders: map[string]Loader{
			"sqs": func(_ context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
				return nil, errors.New("AccessDenied")
			},
		},
	}
	config := Config{AccountID: "055929692761", Regions: []string{"us-east-1"}, Services: []string{"sqs"}}
	if _, err := collector.CollectReport(context.Background(), config); err == nil {
		t.Fatal("CollectReport error = nil, want failure on total read loss")
	}
}

// TestCollectReportFailsConfigLoad proves an unresolvable region fails the
// claim: without credentials or a region there is no scope to scan.
func TestCollectReportFailsConfigLoad(t *testing.T) {
	t.Parallel()

	collector := Collector{
		VerifyIdentity: verifiedIdentity,
		LoadConfig: func(_ context.Context, _ string) (aws.Config, error) {
			return aws.Config{}, errors.New("no credentials")
		},
		Loaders: map[string]Loader{},
	}
	config := Config{AccountID: "055929692761", Regions: []string{"us-east-1"}, Services: []string{"iam"}}
	if _, err := collector.CollectReport(context.Background(), config); err == nil {
		t.Fatal("CollectReport error = nil, want config failure")
	}
}

func TestCollectReportRetainsTypedEC2SourceIdentity(t *testing.T) {
	collector := Collector{
		LoadConfig: fakeConfig(&[]string{}),
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{
			"ec2": func(_ context.Context, cfg aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
				return []collector.Record{
					record("vpc-123", "ec2", cfg.Region, "test", "vpc"),
					record("", "ec2", cfg.Region, "missing", "vpc"),
				}, nil
			},
		},
	}
	outcome, err := collector.CollectReport(context.Background(), Config{
		AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"ec2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Resources) != 1 {
		t.Fatalf("typed resources = %d, want one sourced ID", len(outcome.Resources))
	}
	resource := outcome.Resources[0]
	if resource.ResourceID != "vpc-123" || resource.ResourceType != "aws_ec2_vpc" ||
		resource.Boundary.AccountID != "123456789012" || resource.Boundary.Region != "us-east-1" {
		t.Fatalf("wrong typed source identity: %#v", resource)
	}
}

func TestCollectReportRejectsWrongAccountBeforeServiceRead(t *testing.T) {
	calls := 0
	c := Collector{
		LoadConfig: fakeConfig(&[]string{}),
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "999999999999", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{"ec2": func(context.Context, aws.Config, VerifiedIdentity) ([]collector.Record, error) {
			calls++
			return []collector.Record{record("vpc-123", "ec2", "us-east-1", "tag", "vpc")}, nil
		}},
	}
	_, err := c.CollectReport(context.Background(), Config{AccountID: "055929692761", Regions: []string{"us-east-1"}, Services: []string{"ec2"}})
	if err == nil || calls != 0 {
		t.Fatalf("wrong account err=%v reads=%d, want error before read", err, calls)
	}
}

func TestCollectReportRejectsUnverifiedAccountBeforeServiceRead(t *testing.T) {
	calls := 0
	c := Collector{
		LoadConfig: fakeConfig(&[]string{}),
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{}, errors.New("denied")
		},
		Loaders: map[string]Loader{"ec2": func(context.Context, aws.Config, VerifiedIdentity) ([]collector.Record, error) {
			calls++
			return nil, nil
		}},
	}
	_, err := c.CollectReport(context.Background(), Config{AccountID: "055929692761", Regions: []string{"us-east-1"}, Services: []string{"ec2"}})
	if err == nil || calls != 0 {
		t.Fatalf("unverified account err=%v reads=%d, want error before read", err, calls)
	}
}

func TestCollectReportRejectsWrongPartitionBeforeServiceRead(t *testing.T) {
	calls := 0
	c := Collector{
		LoadConfig: fakeConfig(&[]string{}),
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "055929692761", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{"ec2": func(context.Context, aws.Config, VerifiedIdentity) ([]collector.Record, error) {
			calls++
			return nil, nil
		}},
	}
	_, err := c.CollectReport(context.Background(), Config{AccountID: "055929692761", Regions: []string{"us-gov-west-1"}, Services: []string{"ec2"}})
	if err == nil || calls != 0 {
		t.Fatalf("wrong partition err=%v reads=%d, want error before read", err, calls)
	}
}

func TestIdentityFromCallerValidatesAccountAndARN(t *testing.T) {
	identity, err := identityFromCaller("123456789012", "arn:aws-us-gov:sts::123456789012:assumed-role/read/session")
	if err != nil || identity != (VerifiedIdentity{AccountID: "123456789012", Partition: "aws-us-gov"}) {
		t.Fatalf("caller identity = %+v, %v", identity, err)
	}
	if _, err := identityFromCaller("123456789012", "arn:aws:sts::999999999999:assumed-role/read/session"); err == nil {
		t.Fatal("mismatched STS ARN account accepted")
	}
}

func TestTypedEC2NameMatchesLegacyIdentity(t *testing.T) {
	for _, tt := range []struct{ kind, id, placeholder, want string }{
		{"vpc", "vpc-1", "tag-vpc", "vpc-1"},
		{"subnet", "subnet-1", "tag-subnet", "subnet-1"},
		{"instance", "i-1", "tag-instance", "i-1"},
		{"volume", "vol-1", "tag-volume", "vol-1"},
		{"security-group", "sg-1", "group-name", "group-name"},
		{"security-group-rule", "sgr-1", "sgr-1", "sgr-1"},
		{"network-interface", "eni-1", "eni-1", "eni-1"},
	} {
		got := record(tt.id, "ec2", "us-east-1", tt.placeholder, tt.kind)
		if got.Resource == nil || got.Resource.Name != tt.want {
			t.Errorf("%s typed name = %v, want %q", tt.kind, got.Resource, tt.want)
		}
	}
}

func TestCollectReportCarriesSubnetVPCRelationship(t *testing.T) {
	c := Collector{
		LoadConfig: fakeConfig(&[]string{}), VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{"ec2": func(_ context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
			return []collector.Record{subnetRecord(ec2types.Subnet{
				SubnetId: aws.String("subnet-123"), VpcId: aws.String("vpc-123"),
				SubnetArn: aws.String("arn:aws:ec2:us-east-1:123456789012:subnet/subnet-123"),
			}, "us-east-1")}, nil
		}},
	}
	outcome, err := c.CollectReport(context.Background(), Config{
		AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"ec2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Relationships) != 1 {
		t.Fatalf("relationships = %#v", outcome.Relationships)
	}
	edge := outcome.Relationships[0]
	if edge.Boundary.AccountID != "123456789012" || edge.Boundary.Region != "us-east-1" || edge.RelationshipType != "ec2_subnet_in_vpc" || edge.SourceResourceID != "subnet-123" || edge.TargetResourceID != "vpc-123" {
		t.Fatalf("edge = %#v", edge)
	}
}

func TestCollectReportCarriesNetworkInterfaceRelationships(t *testing.T) {
	c := Collector{
		LoadConfig: fakeConfig(&[]string{}), VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{"ec2": func(_ context.Context, _ aws.Config, identity VerifiedIdentity) ([]collector.Record, error) {
			return []collector.Record{networkInterfaceRecord(ec2types.NetworkInterface{
				NetworkInterfaceId: aws.String("eni-123"), SubnetId: aws.String("subnet-123"),
				VpcId: aws.String("vpc-123"), Groups: []ec2types.GroupIdentifier{{GroupId: aws.String("sg-123")}},
				Attachment: &ec2types.NetworkInterfaceAttachment{InstanceId: aws.String("i-123")},
			}, "us-east-1", identity)}, nil
		}},
	}
	outcome, err := c.CollectReport(context.Background(), Config{
		AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"ec2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Relationships) != 4 || len(outcome.Resources) != 1 {
		t.Fatalf("network interface typed observations = %#v / %#v", outcome.Relationships, outcome.Resources)
	}
	for _, edge := range outcome.Relationships {
		if edge.Boundary.AccountID != "123456789012" || edge.Boundary.Region != "us-east-1" || edge.Boundary.ServiceKind != "ec2" || edge.SourceResourceID != "eni-123" {
			t.Fatalf("unbound network interface edge = %#v", edge)
		}
		edge.Boundary.ScopeID = "scope-123"
		edge.Boundary.GenerationID = "generation-123"
		edge.Boundary.CollectorInstanceID = "collector-123"
		edge.Boundary.ClaimToken = "opaque-claim-token"
		edge.SourceURI = "aws://123456789012"
		fact, err := collector.NewRelationshipFact(edge)
		if err != nil || fact.Kind != collector.AWSKindRelationship {
			t.Fatalf("network interface edge rejected by typed boundary: %#v, %v", fact, err)
		}
	}
}
