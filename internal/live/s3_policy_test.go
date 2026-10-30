// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

func TestS3PolicyPostureDerivesOnlySafeFlags(t *testing.T) {
	const secret = "private-condition-value"
	api := &fakeS3BucketDetails{
		buckets:      &awss3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: aws.String("assets"), BucketRegion: aws.String("us-east-1")}}},
		head:         &awss3.HeadBucketOutput{BucketRegion: aws.String("us-east-1")},
		bucketPolicy: &awss3.GetBucketPolicyOutput{Policy: aws.String(`{"Statement":[{"Effect":"Deny","Principal":"*"},{"Effect":"Allow","Principal":{"AWS":["123456789012","arn:aws:iam::999999999999:role/reader"]},"Condition":{"StringEquals":{"aws:SourceVpce":"` + secret + `"}}}]}`)},
	}
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	rows, err := listS3WithAPI(context.Background(), api, "us-east-1", identity)
	if err != nil || len(rows) != 1 || api.bucketPolicyOwner != identity.AccountID {
		t.Fatalf("policy read failed: rows=%d owner=%q err=%v", len(rows), api.bucketPolicyOwner, err)
	}
	posture := rows[0].S3Posture
	if posture == nil || posture.PolicyPresent == nil || !*posture.PolicyPresent || posture.PolicyGrantsPublic == nil || *posture.PolicyGrantsPublic || posture.PolicyGrantsCrossAccount == nil || !*posture.PolicyGrantsCrossAccount {
		t.Fatalf("wrong derived policy flags")
	}
	if strings.Contains(fmt.Sprint(rows), secret) || strings.Contains(fmt.Sprint(posture), secret) {
		t.Fatal("raw policy leaked into observation")
	}
	api.bucketPolicy.Policy = aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"}}}`)
	rows, err = listS3WithAPI(context.Background(), api, "us-east-1", identity)
	if err != nil || rows[0].S3Posture.PolicyGrantsPublic == nil || !*rows[0].S3Posture.PolicyGrantsPublic {
		t.Fatal("public wildcard was not derived")
	}
	// An unmodelable principal no longer aborts the inventory (proven live:
	// one malformed document stopped every bucket record). The bucket is
	// kept with unknown policy evidence and a warning instead.
	api.bucketPolicy.Policy = aws.String(`{"Statement":{"Effect":"Allow","Principal":{"Unexpected":"*"},"Condition":{"StringEquals":{"aws:SourceVpce":"` + secret + `"}}}}`)
	rows, err = listS3WithAPI(context.Background(), api, "us-east-1", identity)
	var ambiguousDenied *optionalReadDenied
	if !errors.As(err, &ambiguousDenied) || len(rows) != 1 || len(ambiguousDenied.denials) != 1 {
		t.Fatalf("ambiguous policy aborted the inventory: rows=%d err=%v", len(rows), err)
	}
	if ambiguousDenied.denials[0].effect != "policy-unknown" || strings.Contains(fmt.Sprint(rows), secret) {
		t.Fatalf("ambiguous policy warning identity or leak: %+v", ambiguousDenied.denials)
	}
	api.bucketPolicy = &awss3.GetBucketPolicyOutput{}
	rows, err = listS3WithAPI(context.Background(), api, "us-east-1", identity)
	if err != nil || rows[0].S3Posture.PolicyPresent != nil || rows[0].S3Posture.PolicyGrantsPublic != nil {
		t.Fatal("empty successful response was presented as known")
	}
	api.bucketPolicy = nil
	api.bucketPolicyErr = &smithy.GenericAPIError{Code: "NoSuchBucketPolicy"}
	rows, err = listS3WithAPI(context.Background(), api, "us-east-1", identity)
	if err != nil || rows[0].S3Posture.PolicyPresent == nil || *rows[0].S3Posture.PolicyPresent || rows[0].S3Posture.PolicyGrantsPublic != nil {
		t.Fatal("missing policy did not retain known absence and unknown grant")
	}
	api.bucketPolicyErr = &smithy.GenericAPIError{Code: "AccessDenied"}
	if _, err = listS3WithAPI(context.Background(), api, "us-east-1", identity); err == nil {
		t.Fatal("denied required policy read was accepted")
	}
}

func TestS3UnparsablePolicyKeepsBucketWithWarning(t *testing.T) {
	api := &fakeS3BucketDetails{
		buckets:      &awss3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: aws.String("assets"), BucketRegion: aws.String("us-east-1")}}},
		head:         &awss3.HeadBucketOutput{BucketRegion: aws.String("us-east-1")},
		bucketPolicy: &awss3.GetBucketPolicyOutput{Policy: aws.String(`not-json{{{`)},
	}
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	records, err := listS3WithAPI(context.Background(), api, "us-east-1", identity)
	var denied *optionalReadDenied
	if !errors.As(err, &denied) || len(records) != 1 || len(denied.denials) != 1 {
		t.Fatalf("records=%d denials=%+v err=%v", len(records), denied, err)
	}
	entry := denied.denials[0]
	if entry.operation != "GetBucketPolicy" || entry.resource != "bucket:assets" || entry.effect != "policy-unknown" {
		t.Fatalf("warning identity: %+v", entry)
	}
	posture := records[0].S3Posture
	if posture == nil || posture.PolicyPresent != nil || posture.PolicyGrantsPublic != nil || posture.PolicyGrantsCrossAccount != nil {
		t.Fatalf("unparsable policy presented as known: %+v", posture)
	}
	if strings.Contains(fmt.Sprint(records), "not-json") {
		t.Fatal("raw policy leaked into observation")
	}
}
