// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func TestOptionalDenialsAcrossServicesKeepEvidenceAndWarnings(t *testing.T) {
	const account = "123456789012"
	denials := map[string]optionalDenial{
		"ec2":    {operation: "DescribeSecurityGroupRules", resource: "region:us-east-1", effect: "security-group-rules-unavailable"},
		"s3":     {operation: "GetBucketEncryption", resource: "bucket:assets", effect: "encryption-unknown"},
		"lambda": {operation: "ListEventSourceMappings", resource: "arn:aws:lambda:us-east-1:123456789012:function:first", effect: "event-source-mappings-unavailable"},
		"eks":    {operation: "ListOpenIDConnectProviders", resource: "region:us-east-1", effect: "eks-oidc-provider-enrichment-unavailable"},
	}
	loaders := make(map[string]Loader, len(denials))
	for service, denial := range denials {
		loaders[service] = func(_ context.Context, cfg aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
			return []collector.Record{record(service+"-resource", service, cfg.Region, service, "resource")},
				&optionalReadDenied{denials: []optionalDenial{denial}}
		}
	}
	reader := Collector{LoadConfig: fakeConfig(&[]string{}), VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
		return VerifiedIdentity{AccountID: account, Partition: "aws"}, nil
	}, Loaders: loaders}
	outcome, err := reader.CollectReport(context.Background(), Config{AccountID: account, Regions: []string{"us-east-1"}, Services: []string{"ec2", "s3", "lambda", "eks"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Report.Records) != 4 || len(outcome.Warnings) != 4 || len(outcome.WarningObservations) != 4 {
		t.Fatalf("combined outcome: records=%d warnings=%v observations=%v", len(outcome.Report.Records), outcome.Warnings, outcome.WarningObservations)
	}
	seen := map[string]bool{}
	for _, warning := range outcome.WarningObservations {
		want := denials[warning.Boundary.ServiceKind]
		if warning.WarningKind != "permission_denied" || warning.Attributes["operation"] != want.operation || warning.Attributes["resource"] != want.resource || warning.Attributes["effect"] != want.effect {
			t.Fatalf("warning identity: %+v", warning)
		}
		seen[warning.Boundary.ServiceKind] = true
	}
	if len(seen) != len(denials) {
		t.Fatalf("warning service coverage: %v", seen)
	}
	observedAt := time.Now().UTC()
	claim := sdk.Claim{
		ComponentID: collector.ComponentID, InstanceID: "aws-cloud-primary", CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem,
		Scope: sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"}, SourceRunID: "run-1", GenerationID: "generation-1", WorkItemID: "work-1", FencingToken: "fence-1",
		Attempt: 1, Deadline: observedAt.Add(time.Hour), ConfigHandle: "component-config:aws-cloud",
	}
	sourceURI := "aws://123456789012/us-east-1"
	limits := collector.DefaultResourceUse()
	result, err := collector.CollectPartial(claim, outcome.Report, collector.CollectOptions{ObservedAt: observedAt, SourceURI: sourceURI, Limits: limits}, strings.Join(outcome.Warnings, "; "))
	if err != nil {
		t.Fatal(err)
	}
	result, err = collector.AppendLiveWarnings(result, outcome.WarningObservations, sourceURI, limits)
	if err != nil {
		t.Fatal(err)
	}
	warningFacts := 0
	for _, fact := range result.Facts {
		if fact.Kind == collector.AWSKindWarning {
			warningFacts++
		}
	}
	if result.State != sdk.ResultPartial || warningFacts != 4 {
		t.Fatalf("SDK result: state=%s warning facts=%d", result.State, warningFacts)
	}
}
