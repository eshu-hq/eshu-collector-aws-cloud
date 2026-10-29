// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
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
	api.bucketPolicy.Policy = aws.String(`{"Statement":{"Effect":"Allow","Principal":{"Unexpected":"*"},"Condition":{"StringEquals":{"aws:SourceVpce":"` + secret + `"}}}}`)
	if _, err = listS3WithAPI(context.Background(), api, "us-east-1", identity); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("ambiguous policy accepted or raw content leaked")
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
