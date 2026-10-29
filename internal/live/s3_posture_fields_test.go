// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

func TestS3TypedPostureUsesOnlyConfirmedMetadata(t *testing.T) {
	api := &fakeS3BucketDetails{
		buckets:    &awss3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: aws.String("assets"), BucketRegion: aws.String("us-east-1")}}},
		head:       &awss3.HeadBucketOutput{BucketRegion: aws.String("us-east-1")},
		versioning: &awss3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatusEnabled, MFADelete: s3types.MFADeleteStatusDisabled},
		ownership:  &awss3.GetBucketOwnershipControlsOutput{OwnershipControls: &s3types.OwnershipControls{Rules: []s3types.OwnershipControlsRule{{ObjectOwnership: s3types.ObjectOwnershipBucketOwnerEnforced}}}},
		logging:    &awss3.GetBucketLoggingOutput{LoggingEnabled: &s3types.LoggingEnabled{TargetBucket: aws.String("audit")}},
		encryption: &awss3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{Rules: []s3types.ServerSideEncryptionRule{{ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAwsKms, KMSMasterKeyID: aws.String("alias/team")}, BucketKeyEnabled: aws.Bool(true)}}}},
	}
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	rows, err := listS3WithAPI(context.Background(), api, "us-east-1", identity)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	p := rows[0].S3Posture
	if p == nil || p.VersioningStatus == nil || *p.VersioningStatus != "Enabled" || p.VersioningEnabled == nil || !*p.VersioningEnabled || p.MFADeleteEnabled == nil || *p.MFADeleteEnabled || p.ACLDisabled == nil || !*p.ACLDisabled || p.LoggingEnabled == nil || !*p.LoggingEnabled || p.LoggingTargetBucket != "audit" || p.DefaultEncryptionEnabled == nil || !*p.DefaultEncryptionEnabled || p.SSEKMSKeyARN != "alias/team" || p.BucketKeyEnabled == nil || !*p.BucketKeyEnabled {
		t.Fatalf("typed posture = %+v", p)
	}
	api.encryptionErr = &smithy.GenericAPIError{Code: "AccessDenied"}
	rows, err = listS3WithAPI(context.Background(), api, "us-east-1", identity)
	if rows == nil || len(rows) != 1 || err == nil || rows[0].S3Posture.DefaultEncryptionEnabled != nil || rows[0].S3Posture.BucketKeyEnabled != nil {
		t.Fatalf("denied encryption posture: rows=%v err=%v", rows, err)
	}
	api.encryptionErr = nil
	api.encryption = &awss3.GetBucketEncryptionOutput{}
	rows, err = listS3WithAPI(context.Background(), api, "us-east-1", identity)
	if err != nil || rows[0].S3Posture.DefaultEncryptionEnabled != nil {
		t.Fatalf("empty successful encryption response: rows=%v err=%v", rows, err)
	}
}
