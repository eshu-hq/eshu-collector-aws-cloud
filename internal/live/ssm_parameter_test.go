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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"
)

func TestSSMParameterMetadataProducesShareSafeFacts(t *testing.T) {
	modified := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("west", -5*3600))
	row, err := ssmParameterRecord(ssmtypes.ParameterMetadata{
		ARN:  aws.String(" arn:aws:ssm:us-east-1:123456789012:parameter/app/key "),
		Name: aws.String(" /app/key "), Type: ssmtypes.ParameterTypeSecureString,
		Tier: ssmtypes.ParameterTierAdvanced, DataType: aws.String(" text "),
		KeyId: aws.String(" alias/app "), LastModifiedDate: &modified,
		Description: aws.String("secret-description"), AllowedPattern: aws.String("secret-pattern"),
		Policies: []ssmtypes.ParameterInlinePolicy{{PolicyType: aws.String("Expiration"), PolicyStatus: aws.String("Pending"), PolicyText: aws.String("secret-policy-json")}},
	}, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if row.Resource == nil || row.Relationship == nil {
		t.Fatalf("typed SSM output missing: %#v", row)
	}
	if row.Resource.ResourceID != "arn:aws:ssm:us-east-1:123456789012:parameter/app/key" || row.Resource.ResourceType != "aws_ssm_parameter" || row.Resource.Name != "/app/key" || row.Resource.CorrelationAnchors[1] != "/app/key" {
		t.Fatalf("SSM identity: %#v", row.Resource)
	}
	if row.Relationship.RelationshipType != "ssm_parameter_uses_kms_key" || row.Relationship.TargetResourceID != "alias/app" || row.Relationship.TargetARN != "" {
		t.Fatalf("SSM alias relationship: %#v", row.Relationship)
	}
	attrs := row.Resource.Attributes
	if attrs["type"] != "SecureString" || attrs["tier"] != "Advanced" || attrs["description_present"] != true || attrs["allowed_pattern_present"] != true || attrs["last_modified_at"] != modified.UTC() {
		t.Fatalf("SSM metadata: %#v", attrs)
	}
	policies := attrs["policies"].([]map[string]string)
	if len(policies) != 1 || policies[0]["type"] != "Expiration" || policies[0]["status"] != "Pending" {
		t.Fatalf("SSM policy summary: %#v", policies)
	}
	encoded, err := json.Marshal(row.Resource.Attributes)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-description", "secret-pattern", "secret-policy-json", "PolicyText"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("SSM metadata leaked %q: %s", forbidden, encoded)
		}
	}
	missing, err := ssmParameterRecord(ssmtypes.ParameterMetadata{}, "us-east-1")
	if err == nil || missing.Resource != nil {
		t.Fatalf("missing SSM identity must fail: %#v, %v", missing, err)
	}
}

func TestSSMParameterClaimBoundFactsAndLimits(t *testing.T) {
	first, err := ssmParameterRecord(ssmtypes.ParameterMetadata{
		ARN: aws.String("arn:aws:ssm:us-east-1:123456789012:parameter/app/key"), Name: aws.String("/app/key"),
		KeyId: aws.String("arn:aws:kms:us-east-1:123456789012:key/k1"),
	}, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ssmParameterRecord(ssmtypes.ParameterMetadata{Name: aws.String("/app/plain")}, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	loader := Collector{
		LoadConfig: func(_ context.Context, region string) (aws.Config, error) { return aws.Config{Region: region}, nil },
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{"ssm": func(context.Context, aws.Config, VerifiedIdentity) ([]collector.Record, error) {
			return []collector.Record{first, second}, nil
		}},
	}
	outcome, err := loader.CollectReport(context.Background(), Config{AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"ssm"}})
	if err != nil || len(outcome.Report.Records) != 2 || len(outcome.Resources) != 2 || len(outcome.Relationships) != 1 {
		t.Fatalf("SSM outcome: %#v, %v", outcome, err)
	}
	claim := sdk.Claim{ComponentID: collector.ComponentID, InstanceID: "collector", CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem, Scope: sdk.Scope{ID: "scope", Kind: "component"}, GenerationID: "generation", FencingToken: "fence"}
	limits := collector.ResourceUse{MaxRecordsPerClaim: 6, MaxPayloadBytes: 65536}
	base, err := collector.Collect(claim, outcome.Report, collector.CollectOptions{SourceURI: "aws://123456789012", Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := collector.AppendLiveResources(base, outcome.Resources, "aws://123456789012", limits)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := collector.AppendLiveRelationships(resources, outcome.Relationships, "aws://123456789012", limits)
	if err != nil || complete.State != sdk.ResultComplete || len(complete.Facts) != 6 {
		t.Fatalf("SSM six-fact result: %#v, %v", complete, err)
	}
	schemas := map[string]json.RawMessage{}
	for _, kind := range []string{collector.AWSKindResource, collector.AWSKindRelationship} {
		schema, ok := fixturepack.SchemaFor(kind)
		if !ok {
			t.Fatalf("missing %s schema", kind)
		}
		schemas[kind] = schema
	}
	if err := conformance.ValidatePayloadSchemas(schemas, sdk.Result{Facts: complete.Facts[3:]}); err != nil {
		t.Fatalf("SSM typed facts violate pinned schemas: %v", err)
	}
	if complete.Facts[3].SourceRef.URI != "aws://123456789012" || complete.Facts[5].Payload["target_arn"] != "arn:aws:kms:us-east-1:123456789012:key/k1" {
		t.Fatalf("SSM fact provenance/edge: %#v", complete.Facts[3:])
	}
	limits.MaxRecordsPerClaim = 5
	terminal, err := collector.AppendLiveRelationships(resources, outcome.Relationships, "aws://123456789012", limits)
	if err != nil || terminal.State != sdk.ResultTerminal || len(terminal.Facts) != 0 {
		t.Fatalf("SSM over-limit output must fail terminal: %#v, %v", terminal, err)
	}
}

func TestListSSMEmitsOnlyParameterMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Amz-Target") != "AmazonSSM.DescribeParameters" {
			t.Errorf("unexpected SSM operation: %q", request.Header.Get("X-Amz-Target"))
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = writer.Write([]byte(`{"Parameters":[{"ARN":"arn:aws:ssm:us-east-1:123456789012:parameter/app/key","Name":"/app/key","Type":"SecureString","KeyId":"alias/app","Description":"private-description","AllowedPattern":"private-pattern","Policies":[{"PolicyType":"Expiration","PolicyStatus":"Pending","PolicyText":"private-json"}]}]}`))
	}))
	defer server.Close()
	cfg := aws.Config{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: aws.AnonymousCredentials{}, HTTPClient: server.Client(), RetryMaxAttempts: 1}
	records, err := listSSM(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Resource == nil || records[0].Relationship == nil || records[0].Resource.ResourceType != "aws_ssm_parameter" || records[0].Relationship.TargetResourceID != "alias/app" {
		t.Fatalf("SSM DescribeParameters output: %#v", records)
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private-description", "private-pattern", "private-json"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("SSM report leaked %q: %s", forbidden, encoded)
		}
	}
}
