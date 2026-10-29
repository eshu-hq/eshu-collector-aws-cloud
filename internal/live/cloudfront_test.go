// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

func TestCloudFrontDistributionEmitsTypedMetadataAndDependencies(t *testing.T) {
	arn := "arn:aws:cloudfront::123456789012:distribution/EDFDVBD632BHDS5"
	certificate := "arn:aws:acm:us-east-1:123456789012:certificate/cert-1"
	row, err := cloudFrontDistributionRecord(cloudfronttypes.DistributionSummary{
		ARN: aws.String(arn), Id: aws.String("EDFDVBD632BHDS5"), DomainName: aws.String("d111.cloudfront.net"),
		Status: aws.String("Deployed"), WebACLId: aws.String("classic-web-acl"),
		Enabled: aws.Bool(true), Comment: aws.String("orders edge"), HttpVersion: cloudfronttypes.HttpVersionHttp2and3,
		IsIPV6Enabled: aws.Bool(true), LastModifiedTime: aws.Time(time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)),
		PriceClass: cloudfronttypes.PriceClassPriceClass100, Staging: aws.Bool(false),
		Aliases:           &cloudfronttypes.Aliases{Items: []string{"orders.example.com"}},
		Origins:           &cloudfronttypes.Origins{Items: []cloudfronttypes.Origin{{CustomHeaders: &cloudfronttypes.CustomHeaders{Items: []cloudfronttypes.OriginCustomHeader{{HeaderName: aws.String("X-Origin-Auth"), HeaderValue: aws.String("private-value")}}}}}},
		ViewerCertificate: &cloudfronttypes.ViewerCertificate{ACMCertificateArn: aws.String(certificate)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if row.Resource == nil || row.Resource.Region != "aws-global" || row.Resource.ResourceID != arn || row.Resource.Name != "EDFDVBD632BHDS5" || len(row.Relationships) != 2 {
		t.Fatalf("typed distribution = %#v", row)
	}
	for key, want := range map[string]any{"id": "EDFDVBD632BHDS5", "domain_name": "d111.cloudfront.net", "status": "Deployed", "enabled": true, "comment": "orders edge", "http_version": "http2and3", "ipv6_enabled": true, "price_class": "PriceClass_100", "staging": false, "web_acl_id": "classic-web-acl"} {
		if got := row.Resource.Attributes[key]; got != want {
			t.Fatalf("CloudFront attribute %s=%#v, want %#v", key, got, want)
		}
	}
	if row.Resource.Attributes["last_modified_time"] != time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC) {
		t.Fatalf("modified time = %#v", row.Resource.Attributes["last_modified_time"])
	}
	if got := row.Resource.Attributes["aliases"].([]string); len(got) != 1 || got[0] != "orders.example.com" {
		t.Fatalf("aliases=%#v", got)
	}
	if row.Relationships[0].TargetARN != certificate || row.Relationships[1].TargetResourceID != "classic-web-acl" || row.Relationships[1].TargetARN != "" {
		t.Fatalf("dependency edges = %#v", row.Relationships)
	}
	wire, err := json.Marshal(row.Resource.Attributes)
	if err != nil || strings.Contains(string(wire), "private-value") || !strings.Contains(string(wire), "X-Origin-Auth") {
		t.Fatalf("redacted origin metadata = %s, err=%v", wire, err)
	}
}

func TestCloudFrontTypedFactsBoundedAndShareSafe(t *testing.T) {
	first, err := cloudFrontDistributionRecord(cloudfronttypes.DistributionSummary{
		ARN: aws.String("arn:aws:cloudfront::123456789012:distribution/EONE"), Id: aws.String("EONE"),
		Origins:           &cloudfronttypes.Origins{Items: []cloudfronttypes.Origin{{CustomHeaders: &cloudfronttypes.CustomHeaders{Items: []cloudfronttypes.OriginCustomHeader{{HeaderName: aws.String("X-Private"), HeaderValue: aws.String("sensitive-origin-token")}}}}}},
		ViewerCertificate: &cloudfronttypes.ViewerCertificate{ACMCertificateArn: aws.String("arn:aws:acm:us-east-1:123456789012:certificate/cert-1")},
		WebACLId:          aws.String("classic-web-acl"),
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := cloudFrontDistributionRecord(cloudfronttypes.DistributionSummary{
		ARN: aws.String("arn:aws:cloudfront::123456789012:distribution/ETWO"), Id: aws.String("ETWO"),
	})
	if err != nil {
		t.Fatal(err)
	}
	loader := Collector{
		LoadConfig: func(_ context.Context, region string) (aws.Config, error) { return aws.Config{Region: region}, nil },
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{"cloudfront": func(context.Context, aws.Config, VerifiedIdentity) ([]collector.Record, error) {
			return []collector.Record{first, second}, nil
		}},
	}
	outcome, err := loader.CollectReport(context.Background(), Config{AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"cloudfront"}})
	if err != nil || len(outcome.Report.Records) != 2 || len(outcome.Resources) != 2 || len(outcome.Relationships) != 2 {
		t.Fatalf("typed cloudfront outcome = %#v, err=%v", outcome, err)
	}
	claim := sdk.Claim{ComponentID: collector.ComponentID, InstanceID: "collector", CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem, Scope: sdk.Scope{ID: "scope", Kind: "component"}, GenerationID: "generation", FencingToken: "fence"}
	limits := collector.ResourceUse{MaxRecordsPerClaim: 7, MaxPayloadBytes: 65536}
	base, err := collector.Collect(claim, outcome.Report, collector.CollectOptions{SourceURI: "aws://123456789012", Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := collector.AppendLiveResources(base, outcome.Resources, "aws://123456789012", limits)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := collector.AppendLiveRelationships(resources, outcome.Relationships, "aws://123456789012", limits)
	if err != nil || complete.State != sdk.ResultComplete || len(complete.Facts) != 7 {
		t.Fatalf("seven-fact CloudFront result = %#v, err=%v", complete, err)
	}
	schemas := map[string]json.RawMessage{}
	for _, kind := range []string{collector.AWSKindResource, collector.AWSKindRelationship} {
		schema, ok := fixturepack.SchemaFor(kind)
		if !ok {
			t.Fatalf("pinned fixture pack lacks %s schema", kind)
		}
		schemas[kind] = schema
	}
	if err := conformance.ValidatePayloadSchemas(schemas, sdk.Result{Facts: complete.Facts[3:]}); err != nil {
		t.Fatalf("emitted CloudFront payloads violate pinned schemas: %v", err)
	}
	for _, fact := range complete.Facts {
		if fact.Kind != collector.AWSKindResource && fact.Kind != collector.AWSKindRelationship {
			continue
		}
		wire, err := json.Marshal(fact.Payload)
		if err != nil || strings.Contains(string(wire), "sensitive-origin-token") {
			t.Fatalf("unsafe fact payload = %s, err=%v", wire, err)
		}
		if fact.Kind == collector.AWSKindResource && (!strings.Contains(string(wire), "aws-global") || !strings.Contains(string(wire), "aws_cloudfront_distribution")) {
			t.Fatalf("resource identity = %s", wire)
		}
	}
	limits.MaxRecordsPerClaim = 6
	limited, err := collector.AppendLiveRelationships(resources, outcome.Relationships, "aws://123456789012", limits)
	if err != nil || limited.State != sdk.ResultTerminal || len(limited.Facts) != 0 {
		t.Fatalf("six-fact bound must fail terminal, got %#v, err=%v", limited, err)
	}
}

func TestCloudFrontDistributionRejectsMissingIdentity(t *testing.T) {
	if _, err := cloudFrontDistributionRecord(cloudfronttypes.DistributionSummary{}); err == nil {
		t.Fatal("missing ARN, ID and domain must fail instead of publishing a placeholder")
	}
}
