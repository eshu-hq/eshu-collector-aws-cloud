// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	awssnstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// Homed rows for the custodial successor to the retired cloudfront/sns peer
// lanes (eshu-hq/eshu#8852, arbiter-waived no-takeover): typed CloudFront
// distribution homes, typed SNS topic homes with GetTopicAttributes
// enrichment, and SNS delivers-to edges. The census pairs in
// row_census_test.go prove these rows; the envelope tests below prove they
// pass the SDK share-safe guard that blocked #53/#54.
func TestHomeCloudFrontDistribution(t *testing.T) {
	distribution := cloudfronttypes.DistributionSummary{
		ARN:                  aws.String("arn:aws:cloudfront::123456789012:distribution/E1234"),
		Id:                   aws.String("E1234"),
		DomainName:           aws.String("d1234.cloudfront.net"),
		Status:               aws.String("Deployed"),
		Enabled:              aws.Bool(true),
		Comment:              aws.String("cdn"),
		HttpVersion:          "http2",
		IsIPV6Enabled:        aws.Bool(true),
		PriceClass:           "PriceClass_100",
		Staging:              aws.Bool(false),
		WebACLId:             aws.String("arn:aws:wafv2:us-east-1:123456789012:global/webacl/x/1"),
		Aliases:              &cloudfronttypes.Aliases{Items: []string{"cdn.example.com"}},
		Origins:              &cloudfronttypes.Origins{Items: []cloudfronttypes.Origin{{Id: aws.String("o1"), DomainName: aws.String("x.s3.amazonaws.com")}}},
		DefaultCacheBehavior: &cloudfronttypes.DefaultCacheBehavior{TargetOriginId: aws.String("o1"), ViewerProtocolPolicy: "redirect-to-https"},
		ViewerCertificate:    &cloudfronttypes.ViewerCertificate{CloudFrontDefaultCertificate: aws.Bool(true)},
	}
	got := cloudFrontDistributionRecord(distribution, "us-east-1")
	if got.Resource == nil {
		t.Fatal("distribution typed resource missing")
	}
	resource := got.Resource
	if resource.ResourceType != "aws_cloudfront_distribution" {
		t.Fatalf("distribution resource type = %q", resource.ResourceType)
	}
	if resource.ResourceID != "arn:aws:cloudfront::123456789012:distribution/E1234" || resource.Name != "d1234.cloudfront.net" {
		t.Fatalf("distribution identity = %+v", resource)
	}
	if resource.Attributes["comment"] != "cdn" || resource.Attributes["price_class"] != "PriceClass_100" {
		t.Fatalf("distribution attributes = %#v", resource.Attributes)
	}
	if resource.Attributes["enabled"] != true || resource.Attributes["ipv6_enabled"] != true {
		t.Fatalf("distribution flags = %#v", resource.Attributes)
	}
	origins, ok := resource.Attributes["origins"].([]map[string]any)
	if !ok || len(origins) != 1 || origins[0]["id"] != "o1" {
		t.Fatalf("distribution origins = %#v", resource.Attributes["origins"])
	}
	behavior, ok := resource.Attributes["default_cache_behavior"].(map[string]any)
	if !ok || behavior["target_origin_id"] != "o1" {
		t.Fatalf("distribution default cache behavior = %#v", resource.Attributes["default_cache_behavior"])
	}
	certificate, ok := resource.Attributes["viewer_certificate"].(map[string]any)
	if !ok || certificate["cloudfront_default_certificate"] != true {
		t.Fatalf("distribution viewer certificate = %#v", resource.Attributes["viewer_certificate"])
	}
	if resource.Attributes["tags"] != nil {
		t.Fatalf("distribution tags must stay nil (no ListTagsForResource call), got %#v", resource.Attributes["tags"])
	}
	if !got.TypedOnly {
		t.Fatal("distribution row must set TypedOnly")
	}
}

func TestHomeCloudFrontDistributionEnvelopeAdmits(t *testing.T) {
	distribution := cloudfronttypes.DistributionSummary{
		ARN:        aws.String("arn:aws:cloudfront::123456789012:distribution/E1234"),
		Id:         aws.String("E1234"),
		DomainName: aws.String("d1234.cloudfront.net"),
		Status:     aws.String("Deployed"),
		Enabled:    aws.Bool(true),
	}
	got := cloudFrontDistributionRecord(distribution, "us-east-1")
	observation := collector.ResourceObservation{
		Boundary: wave1Boundary("123456789012", "us-east-1", got.Resource.ServiceKind),
		ARN:      got.Resource.ARN, ResourceID: got.Resource.ResourceID,
		ResourceType: got.Resource.ResourceType, Name: got.Resource.Name,
		State: got.Resource.State, Tags: got.Resource.Tags,
		Attributes:         got.Resource.Attributes,
		CorrelationAnchors: append([]string(nil), got.Resource.CorrelationAnchors...),
		SourceRecordID:     got.Resource.SourceRecordID,
		SourceURI:          "aws://123456789012",
	}
	if _, err := collector.NewResourceFact(observation); err != nil {
		t.Fatalf("homed distribution observation must envelope cleanly: %v", err)
	}
}

func TestHomeSNSTopic(t *testing.T) {
	attrs := map[string]string{
		"TopicArn": "arn:aws:sns:us-east-1:123456789012:orders", "DisplayName": "orders",
		"Owner": "123456789012", "FifoTopic": "false", "KmsMasterKeyId": "alias/aws/sns",
		"SubscriptionsConfirmed": "2", "SignatureVersion": "1", "TracingConfig": "Active",
	}
	got := snsTopicRecord("arn:aws:sns:us-east-1:123456789012:orders", attrs, "us-east-1")
	if got.Resource == nil {
		t.Fatal("topic typed resource missing")
	}
	resource := got.Resource
	if resource.ResourceType != "aws_sns_topic" {
		t.Fatalf("topic resource type = %q", resource.ResourceType)
	}
	if resource.Name != "orders" || resource.ResourceID != "arn:aws:sns:us-east-1:123456789012:orders" {
		t.Fatalf("topic identity = %+v", resource)
	}
	if resource.Attributes["display_name"] != "orders" || resource.Attributes["owner"] != "123456789012" {
		t.Fatalf("topic attributes = %#v", resource.Attributes)
	}
	if resource.Attributes["fifo_topic"] != false || resource.Attributes["kms_master_key_id"] != "alias/aws/sns" {
		t.Fatalf("topic delivery attributes = %#v", resource.Attributes)
	}
	if !got.TypedOnly {
		t.Fatal("topic row must set TypedOnly")
	}
}

func TestHomeSNSTopicBareRowOnDeniedAttributes(t *testing.T) {
	got := snsTopicRecord("arn:aws:sns:us-east-1:123456789012:orders", map[string]string{}, "us-east-1")
	if got.Resource == nil {
		t.Fatal("denied topic must keep its bare typed row")
	}
	if got.Resource.ResourceID != "arn:aws:sns:us-east-1:123456789012:orders" {
		t.Fatalf("bare topic identity = %+v", got.Resource)
	}
}

func TestHomeSNSTopicEnvelopeAdmits(t *testing.T) {
	attrs := map[string]string{
		"TopicArn": "arn:aws:sns:us-east-1:123456789012:orders", "DisplayName": "orders",
		"Owner": "123456789012",
	}
	got := snsTopicRecord("arn:aws:sns:us-east-1:123456789012:orders", attrs, "us-east-1")
	observation := collector.ResourceObservation{
		Boundary: wave1Boundary("123456789012", "us-east-1", got.Resource.ServiceKind),
		ARN:      got.Resource.ARN, ResourceID: got.Resource.ResourceID,
		ResourceType: got.Resource.ResourceType, Name: got.Resource.Name,
		State: got.Resource.State, Tags: got.Resource.Tags,
		Attributes:         got.Resource.Attributes,
		CorrelationAnchors: append([]string(nil), got.Resource.CorrelationAnchors...),
		SourceRecordID:     got.Resource.SourceRecordID,
		SourceURI:          "aws://123456789012",
	}
	if _, err := collector.NewResourceFact(observation); err != nil {
		t.Fatalf("homed topic observation must envelope cleanly: %v", err)
	}
}

func TestHomeSNSSubscription(t *testing.T) {
	subscription := awssnstypes.Subscription{
		TopicArn:        aws.String("arn:aws:sns:us-east-1:123456789012:orders"),
		SubscriptionArn: aws.String("arn:aws:sns:us-east-1:123456789012:orders:1111"),
		Protocol:        aws.String("sqs"),
		Endpoint:        aws.String("arn:aws:sqs:us-east-1:123456789012:fulfilment"),
		Owner:           aws.String("123456789012"),
	}
	edge, ok := snsSubscriptionRelationship("arn:aws:sns:us-east-1:123456789012:orders", subscription, "us-east-1")
	if !ok {
		t.Fatal("ARN-endpoint subscription must produce an edge")
	}
	if edge.RelationshipType != "sns_topic_delivers_to_resource" {
		t.Fatalf("edge type = %q", edge.RelationshipType)
	}
	if edge.SourceARN != "arn:aws:sns:us-east-1:123456789012:orders" || edge.TargetARN != "arn:aws:sqs:us-east-1:123456789012:fulfilment" {
		t.Fatalf("edge endpoints = %+v", edge)
	}
	if edge.TargetType != "aws_sqs_queue" {
		t.Fatalf("edge target type = %q", edge.TargetType)
	}
}

func TestHomeSNSSubscriptionSkipsEmailEndpoints(t *testing.T) {
	subscription := awssnstypes.Subscription{
		TopicArn:        aws.String("arn:aws:sns:us-east-1:123456789012:orders"),
		SubscriptionArn: aws.String("pending"),
		Protocol:        aws.String("email"),
		Endpoint:        aws.String("ops@example.com"),
	}
	if _, ok := snsSubscriptionRelationship("arn:aws:sns:us-east-1:123456789012:orders", subscription, "us-east-1"); ok {
		t.Fatal("email endpoint must produce no edge, matching the in-tree skip")
	}
}
