// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"
)

func TestSNSSubscriptionRelationshipExcludesPrivateEndpoints(t *testing.T) {
	topicARN := "arn:aws:sns:us-east-1:123456789012:orders"
	queueARN := "arn:aws:sqs:us-east-1:123456789012:orders"
	row := snsSubscriptionRecord(topicARN, "us-east-1", snstypes.Subscription{
		SubscriptionArn: aws.String("arn:aws:sns:us-east-1:123456789012:orders:sub-1"),
		Endpoint:        aws.String("  " + queueARN + "  "), Protocol: aws.String("sqs"), Owner: aws.String("123456789012"),
	})
	if len(row.Relationships) != 1 || row.Relationships[0].RelationshipType != "sns_topic_delivers_to_resource" || row.Relationships[0].TargetResourceID != queueARN || row.Relationships[0].TargetType != "aws_sqs_queue" {
		t.Fatalf("SNS queue relationship = %#v", row.Relationships)
	}
	for _, endpoint := range []string{"private@example.com", "+15551234567", "https://example.com/private"} {
		private := snsSubscriptionRecord(topicARN, "us-east-1", snstypes.Subscription{Endpoint: aws.String(endpoint), Protocol: aws.String("https")})
		if len(private.Relationships) != 0 {
			t.Fatalf("private endpoint %q produced relationship: %#v", endpoint, private.Relationships)
		}
	}
}

func TestListSNSRetainsOnlyARNEndpointRelationship(t *testing.T) {
	topicARN := "arn:aws:sns:us-east-1:123456789012:orders"
	queueARN := "arn:aws:sqs:us-east-1:123456789012:orders"
	const prefix = `<ResponseMetadata><RequestId>test</RequestId></ResponseMetadata>`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Errorf("parse SNS request: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "text/xml")
		switch request.Form.Get("Action") {
		case "ListTopics":
			_, _ = writer.Write([]byte(`<ListTopicsResponse><ListTopicsResult><Topics><member><TopicArn>` + topicARN + `</TopicArn></member></Topics></ListTopicsResult>` + prefix + `</ListTopicsResponse>`))
		case "ListSubscriptionsByTopic":
			_, _ = writer.Write([]byte(`<ListSubscriptionsByTopicResponse><ListSubscriptionsByTopicResult><Subscriptions>` +
				`<member><SubscriptionArn>arn:aws:sns:us-east-1:123456789012:orders:sub-1</SubscriptionArn><Endpoint>` + queueARN + `</Endpoint><Protocol>sqs</Protocol><Owner>123456789012</Owner></member>` +
				`<member><SubscriptionArn>arn:aws:sns:us-east-1:123456789012:orders:sub-2</SubscriptionArn><Endpoint>private@example.com</Endpoint><Protocol>email</Protocol></member>` +
				`</Subscriptions></ListSubscriptionsByTopicResult>` + prefix + `</ListSubscriptionsByTopicResponse>`))
		default:
			t.Errorf("unexpected SNS action %q", request.Form.Get("Action"))
			writer.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	cfg := aws.Config{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: aws.AnonymousCredentials{}, HTTPClient: server.Client(), RetryMaxAttempts: 1}
	records, err := listSNS(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 || len(records[0].Relationships) != 0 || len(records[1].Relationships) != 1 || len(records[2].Relationships) != 0 || records[1].Relationships[0].TargetARN != queueARN {
		t.Fatalf("SNS production rows = %#v", records)
	}
}

func TestSNSARNRelationshipEmitsBoundedShareSafeFact(t *testing.T) {
	topicARN := "arn:aws:sns:us-east-1:123456789012:orders"
	queueARN := "arn:aws:sqs:us-east-1:123456789012:orders"
	queue := snsSubscriptionRecord(topicARN, "us-east-1", snstypes.Subscription{
		SubscriptionArn: aws.String("arn:aws:sns:us-east-1:123456789012:orders:sub-1"),
		Endpoint:        aws.String(queueARN), Protocol: aws.String("sqs"), Owner: aws.String("123456789012"),
	})
	private := snsSubscriptionRecord(topicARN, "us-east-1", snstypes.Subscription{
		SubscriptionArn: aws.String("arn:aws:sns:us-east-1:123456789012:orders:sub-2"),
		Endpoint:        aws.String("private@example.com"), Protocol: aws.String("email"),
	})
	loader := Collector{
		LoadConfig: func(_ context.Context, region string) (aws.Config, error) { return aws.Config{Region: region}, nil },
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{"sns": func(context.Context, aws.Config, VerifiedIdentity) ([]collector.Record, error) {
			return []collector.Record{record(topicARN, "sns", "us-east-1", "orders", "topic"), queue, private}, nil
		}},
	}
	outcome, err := loader.CollectReport(context.Background(), Config{AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"sns"}})
	if err != nil || len(outcome.Report.Records) != 3 || len(outcome.Relationships) != 1 {
		t.Fatalf("SNS outcome records=%d relationships=%d err=%v", len(outcome.Report.Records), len(outcome.Relationships), err)
	}
	claim := sdk.Claim{ComponentID: collector.ComponentID, InstanceID: "collector", CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem, Scope: sdk.Scope{ID: "scope", Kind: "component"}, GenerationID: "generation", FencingToken: "fence"}
	limits := collector.ResourceUse{MaxRecordsPerClaim: 5, MaxPayloadBytes: 65536}
	base, err := collector.Collect(claim, outcome.Report, collector.CollectOptions{SourceURI: "aws://123456789012", Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	complete, err := collector.AppendLiveRelationships(base, outcome.Relationships, "aws://123456789012", limits)
	if err != nil || complete.State != sdk.ResultComplete || len(complete.Facts) != 5 {
		t.Fatalf("SNS five-fact result = %#v, err=%v", complete, err)
	}
	schema, ok := fixturepack.SchemaFor(collector.AWSKindRelationship)
	if !ok {
		t.Fatal("pinned relationship schema missing")
	}
	if err := conformance.ValidatePayloadSchemas(map[string]json.RawMessage{collector.AWSKindRelationship: schema}, sdk.Result{Facts: complete.Facts[4:]}); err != nil {
		t.Fatalf("SNS fact violates pinned schema: %v", err)
	}
	fact := complete.Facts[4]
	if fact.Kind != collector.AWSKindRelationship || fact.SourceRef.ScopeID != "scope" || fact.SourceRef.GenerationID != "generation" || fact.SourceRef.RecordID != "arn:aws:sns:us-east-1:123456789012:orders:sub-1" {
		t.Fatalf("SNS relationship provenance = %#v", fact)
	}
	for key, want := range map[string]any{"relationship_type": "sns_topic_delivers_to_resource", "source_resource_id": topicARN, "target_resource_id": queueARN, "source_arn": topicARN, "target_arn": queueARN, "target_type": "aws_sqs_queue"} {
		if got := fact.Payload[key]; got != want {
			t.Fatalf("SNS payload %s=%#v, want %#v", key, got, want)
		}
	}
	metadata, ok := fact.Payload["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("SNS attributes missing: %#v", fact.Payload)
	}
	attrs := metadata
	if attrs["owner"] != "123456789012" || attrs["protocol"] != "sqs" || attrs["subscription_arn"] != "arn:aws:sns:us-east-1:123456789012:orders:sub-1" {
		t.Fatalf("SNS reported attributes = %#v", metadata)
	}
	wire, err := json.Marshal(fact)
	if err != nil || strings.Contains(string(wire), "private@example.com") || strings.Contains(string(wire), "https://") {
		t.Fatalf("SNS fact leaked private endpoint: %s, err=%v", wire, err)
	}
	fullWire, err := json.Marshal(complete)
	if err != nil || strings.Contains(string(fullWire), "private@example.com") {
		t.Fatalf("SNS result leaked private endpoint: %s, err=%v", fullWire, err)
	}
	limited := limits
	limited.MaxRecordsPerClaim = 4
	terminal, err := collector.AppendLiveRelationships(base, outcome.Relationships, "aws://123456789012", limited)
	if err != nil || terminal.State != sdk.ResultTerminal || len(terminal.Facts) != 0 {
		t.Fatalf("SNS budget overflow = %#v, err=%v", terminal, err)
	}
}
