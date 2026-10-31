// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// lane0S3LivePolicyDocument is one public-grant bucket policy for the live
// path: no raw text may survive the read.
const lane0S3LivePolicyDocument = `{"Version":"2012-10-17","Statement":{"Sid":"LivePublic","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::assets/*"}}`

func lane0S3LiveAPIWithPolicy() *fakeS3BucketDetails {
	return &fakeS3BucketDetails{
		buckets:      &awss3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: aws.String("assets"), BucketRegion: aws.String("us-east-1")}}},
		head:         &awss3.HeadBucketOutput{BucketRegion: aws.String("us-east-1")},
		bucketPolicy: &awss3.GetBucketPolicyOutput{Policy: aws.String(lane0S3LivePolicyDocument)},
	}
}

func TestS3LivePolicyFactsReachRecord(t *testing.T) {
	t.Parallel()

	rows, err := listS3WithAPI(context.Background(), lane0S3LiveAPIWithPolicy(), "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if len(row.S3Grants) != 1 || !row.S3Grants[0].Public || row.S3Grants[0].SourceStatementID != "LivePublic" {
		t.Fatalf("S3Grants = %+v", row.S3Grants)
	}
	if len(row.ResourcePolicyStatements) != 1 || !row.ResourcePolicyStatements[0].IsPublic || row.ResourcePolicyStatements[0].StatementSID != "LivePublic" {
		t.Fatalf("ResourcePolicyStatements = %+v", row.ResourcePolicyStatements)
	}
	if row.S3Grants[0].BucketARN != row.Resource.ARN || row.ResourcePolicyStatements[0].ResourceARN != row.Resource.ARN {
		t.Fatalf("policy fact bucket identity detached from resource: %+v %+v", row.S3Grants[0], row.ResourcePolicyStatements[0])
	}
	// The derived observations must feed the emitted builders end to end:
	// no builder rejection, no raw text in the fact payload.
	grantFact, err := collector.NewS3ExternalPrincipalGrantFact(bindLane0Grant(row.S3Grants[0]))
	if err != nil {
		t.Fatal(err)
	}
	if grantFact.Kind != collector.AWSKindS3ExternalPrincipalGrant || grantFact.Payload["is_public"] != true {
		t.Fatalf("grant fact = %q %#v", grantFact.Kind, grantFact.Payload)
	}
	statementFact, err := collector.NewResourcePolicyPermissionFact(bindLane0Statement(row.ResourcePolicyStatements[0]))
	if err != nil {
		t.Fatal(err)
	}
	if statementFact.Kind != collector.AWSKindResourcePolicyPermission || statementFact.Payload["is_public"] != true {
		t.Fatalf("statement fact = %q %#v", statementFact.Kind, statementFact.Payload)
	}
}

func lane0ClaimBoundary() collector.Boundary {
	return collector.Boundary{
		AccountID: "123456789012", Region: "us-east-1", ServiceKind: "s3",
		ScopeID: "aws:123456789012:us-east-1", GenerationID: "aws:123456789012:us-east-1:lane0:1",
		CollectorInstanceID: "aws-lane0-1", ClaimToken: "lane0-fencing-token",
	}
}

func bindLane0Grant(observation collector.S3ExternalPrincipalGrantObservation) collector.S3ExternalPrincipalGrantObservation {
	observation.Boundary = lane0ClaimBoundary()
	observation.SourceURI = "aws:s3:bucket/assets"
	return observation
}

func bindLane0Statement(observation collector.ResourcePolicyPermissionObservation) collector.ResourcePolicyPermissionObservation {
	observation.Boundary = lane0ClaimBoundary()
	observation.SourceURI = "aws:s3:bucket/assets"
	return observation
}

func TestCollectReportCarriesS3PolicyFacts(t *testing.T) {
	t.Parallel()

	c := Collector{
		LoadConfig: fakeConfig(&[]string{}), VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{"s3": func(_ context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
			return []collector.Record{{
				S3Grants: []collector.S3ExternalPrincipalGrantObservation{{
					Boundary:    collector.Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "s3"},
					BucketARN:   "arn:aws:s3:::assets", BucketName: "assets",
					PrincipalKind: "public", PrincipalValue: "*", GrantOutcome: "public", Public: true,
				}},
				ResourcePolicyStatements: []collector.ResourcePolicyPermissionObservation{{
					Boundary:     collector.Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "s3"},
					ResourceARN:  "arn:aws:s3:::assets", ResourceType: "aws_s3_bucket",
					StatementSID: "LivePublic", Effect: "Allow", IsPublic: true,
				}},
			}}, nil
		}},
	}
	outcome, err := c.CollectReport(context.Background(), Config{
		AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"s3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.S3Grants) != 1 || outcome.S3Grants[0].Boundary.AccountID != "123456789012" {
		t.Fatalf("S3Grants = %+v", outcome.S3Grants)
	}
	if len(outcome.ResourcePolicyPermissions) != 1 || outcome.ResourcePolicyPermissions[0].Boundary.AccountID != "123456789012" {
		t.Fatalf("ResourcePolicyPermissions = %+v", outcome.ResourcePolicyPermissions)
	}

	// Production path: the exact shared function collectLivePlan calls.
	// Dropping either family from AppendOutcomeFacts fails here instead of
	// silently emitting zero new-kind facts in production.
	observedAt := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	result := sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultComplete,
		Claim: sdk.Claim{
			ComponentID: collector.ComponentID, InstanceID: "aws-parity-s3",
			CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem,
			Scope:       sdk.Scope{ID: "aws:123456789012:us-east-1", Kind: "component"},
			SourceRunID: "s3-parity-run", GenerationID: "aws:123456789012:us-east-1:s3:1",
			WorkItemID: "s3-parity-work", FencingToken: "s3-parity-token",
			Attempt: 1, Deadline: observedAt.Add(time.Hour), ConfigHandle: "component-config:aws-cloud",
		},
		Generation: sdk.Generation{ID: "aws:123456789012:us-east-1:s3:1", ObservedAt: observedAt},
	}
	if result, err = AppendOutcomeFacts(result, outcome, "aws:s3:us-east-1:s3-parity", collector.DefaultResourceUse()); err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.NewValidator(collector.Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected pipeline result carrying policy facts: %v", err)
	}
	want := map[string]bool{"s3_external_principal_grant": false, "aws_resource_policy_permission": false}
	for _, fact := range result.Facts {
		if _, ok := want[fact.Kind]; ok {
			want[fact.Kind] = true
		}
	}
	for kind, found := range want {
		if !found {
			t.Errorf("pipeline result missing emitted fact kind %q", kind)
		}
	}
}
