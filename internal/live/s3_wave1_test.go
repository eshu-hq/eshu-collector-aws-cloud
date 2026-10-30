// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"testing"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

func wave1S3LiveAPI() *fakeS3BucketDetails {
	return &fakeS3BucketDetails{
		buckets:    &awss3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: aws.String("assets"), BucketRegion: aws.String("us-east-1")}}},
		head:       &awss3.HeadBucketOutput{BucketRegion: aws.String("us-east-1")},
		versioning: &awss3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatusEnabled},
		publicAccess: &awss3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls: aws.Bool(true), IgnorePublicAcls: aws.Bool(true),
			BlockPublicPolicy: aws.Bool(true), RestrictPublicBuckets: aws.Bool(true),
		}},
		logging: &awss3.GetBucketLoggingOutput{LoggingEnabled: &s3types.LoggingEnabled{
			TargetBucket: aws.String("audit"), TargetPrefix: aws.String("logs/"),
		}},
	}
}

func wave1S3LiveRows(t *testing.T, api *fakeS3BucketDetails) []collector.Record {
	t.Helper()
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	rows, err := listS3WithAPI(context.Background(), api, "us-east-1", identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	return rows
}

func TestS3PostureCarriesPublicAccessBlockFlags(t *testing.T) {
	t.Parallel()

	api := wave1S3LiveAPI()
	posture := wave1S3LiveRows(t, api)[0].S3Posture
	if posture == nil {
		t.Fatal("S3Posture is nil")
	}
	for _, flag := range []*bool{
		posture.BlockPublicACLs, posture.IgnorePublicACLs,
		posture.BlockPublicPolicy, posture.RestrictPublicBuckets,
		posture.BlockPublicAccessAllEnabled,
	} {
		if flag == nil || !*flag {
			t.Fatalf("posture PAB flags = %+v", posture)
		}
	}

	api.publicAccess.PublicAccessBlockConfiguration.IgnorePublicAcls = aws.Bool(false)
	posture = wave1S3LiveRows(t, api)[0].S3Posture
	if posture.IgnorePublicACLs == nil || *posture.IgnorePublicACLs {
		t.Fatalf("IgnorePublicACLs = %+v", posture.IgnorePublicACLs)
	}
	if posture.BlockPublicAccessAllEnabled == nil || *posture.BlockPublicAccessAllEnabled {
		t.Fatalf("BlockPublicAccessAllEnabled = %+v", posture.BlockPublicAccessAllEnabled)
	}
	if posture.BlockPublicACLs == nil || !*posture.BlockPublicACLs {
		t.Fatalf("BlockPublicACLs = %+v", posture.BlockPublicACLs)
	}

	api.publicAccess = nil
	api.publicAccessErr = &smithy.GenericAPIError{Code: "NoSuchPublicAccessBlockConfiguration"}
	posture = wave1S3LiveRows(t, api)[0].S3Posture
	for _, flag := range []*bool{
		posture.BlockPublicACLs, posture.IgnorePublicACLs,
		posture.BlockPublicPolicy, posture.RestrictPublicBuckets,
		posture.BlockPublicAccessAllEnabled,
	} {
		if flag != nil {
			t.Fatalf("absent PAB configuration leaked a value: %+v", posture)
		}
	}
}

func TestS3LoggingEdgeFollowsTarget(t *testing.T) {
	t.Parallel()

	api := wave1S3LiveAPI()
	rows := wave1S3LiveRows(t, api)
	edges := rows[0].Relationships
	if len(edges) != 1 {
		t.Fatalf("relationships = %+v, want 1 logging edge", edges)
	}
	edge := edges[0]
	if edge.RelationshipType != catalog.RelationshipS3BucketLogsToBucket {
		t.Fatalf("relationship type = %q", edge.RelationshipType)
	}
	if edge.SourceARN != "arn:aws:s3:::assets" || edge.TargetARN != "arn:aws:s3:::audit" {
		t.Fatalf("edge endpoints = %q -> %q", edge.SourceARN, edge.TargetARN)
	}
	if edge.SourceRecordID != "arn:aws:s3:::assets->logging:audit" {
		t.Fatalf("record ID = %q", edge.SourceRecordID)
	}
	if edge.Attributes["target_prefix"] != "logs/" || edge.TargetType != catalog.ResourceTypeS3Bucket {
		t.Fatalf("edge = %+v", edge)
	}

	api.logging = &awss3.GetBucketLoggingOutput{}
	rows = wave1S3LiveRows(t, api)
	if len(rows[0].Relationships) != 0 {
		t.Fatalf("targetless bucket emitted edges: %+v", rows[0].Relationships)
	}
}

func TestS3LoggingRelationshipBuilderGuards(t *testing.T) {
	t.Parallel()

	if _, ok := s3LoggingRelationship("us-east-1", "", "audit", "logs/", "aws"); ok {
		t.Fatal("blank source accepted")
	}
	if _, ok := s3LoggingRelationship("us-east-1", "arn:aws:s3:::assets", "  ", "logs/", "aws"); ok {
		t.Fatal("blank target accepted")
	}
	edge, ok := s3LoggingRelationship("us-east-1", "arn:aws:s3:::assets", "audit", "logs/", "aws")
	if !ok || edge.TargetARN != "arn:aws:s3:::audit" || edge.ServiceKind != catalog.ServiceS3 {
		t.Fatalf("edge = %+v, %t", edge, ok)
	}
	if got := s3BlockPublicAccessAll(nil, nil, nil, nil); got != nil {
		t.Fatalf("absent flags = %v, want nil", *got)
	}
	if s3PostureFlag("true") != nil {
		t.Fatal("non-bool flag value accepted")
	}
}
