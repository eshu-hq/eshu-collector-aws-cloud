// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

func fakeConfig(regions *[]string) func(context.Context, string) (aws.Config, error) {
	return func(_ context.Context, region string) (aws.Config, error) {
		*regions = append(*regions, region)
		return aws.Config{Region: region}, nil
	}
}

// TestCollectReportListsOnlyAllowlistedServices proves the orchestrator calls
// exactly the configured service-region pairs: nothing outside the host
// allowlists is ever read.
func TestCollectReportListsOnlyAllowlistedServices(t *testing.T) {
	t.Parallel()

	var regions []string
	calls := map[string]int{}
	collector := Collector{
		LoadConfig: fakeConfig(&regions),
		Loaders: map[string]Loader{
			"iam": func(_ context.Context, cfg aws.Config) ([]collector.Record, error) {
				calls["iam/"+cfg.Region]++
				return []collector.Record{{ID: "arn:role", Name: "role", Detail: "d"}}, nil
			},
			"sqs": func(_ context.Context, cfg aws.Config) ([]collector.Record, error) {
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
		LoadConfig: fakeConfig(&[]string{}),
		Loaders: map[string]Loader{
			"iam": func(_ context.Context, _ aws.Config) ([]collector.Record, error) {
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
		LoadConfig: fakeConfig(&[]string{}),
		Loaders: map[string]Loader{
			"iam": func(_ context.Context, _ aws.Config) ([]collector.Record, error) {
				return []collector.Record{{ID: "arn:role", Name: "role"}}, nil
			},
			"sqs": func(_ context.Context, _ aws.Config) ([]collector.Record, error) {
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
		LoadConfig: fakeConfig(&[]string{}),
		Loaders: map[string]Loader{
			"sqs": func(_ context.Context, _ aws.Config) ([]collector.Record, error) {
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
