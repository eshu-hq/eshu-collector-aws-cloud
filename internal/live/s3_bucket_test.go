// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"testing"
	"time"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type fakeS3BucketDetails struct {
	head      *awss3.HeadBucketOutput
	tags      *awss3.GetBucketTaggingOutput
	headErr   error
	tagsErr   error
	headOwner string
	tagOwner  string
}

func (f *fakeS3BucketDetails) HeadBucket(_ context.Context, input *awss3.HeadBucketInput, _ ...func(*awss3.Options)) (*awss3.HeadBucketOutput, error) {
	f.headOwner = aws.ToString(input.ExpectedBucketOwner)
	return f.head, f.headErr
}

func (f *fakeS3BucketDetails) GetBucketTagging(_ context.Context, input *awss3.GetBucketTaggingInput, _ ...func(*awss3.Options)) (*awss3.GetBucketTaggingOutput, error) {
	f.tagOwner = aws.ToString(input.ExpectedBucketOwner)
	return f.tags, f.tagsErr
}

func TestS3BucketDetailsPreserveTagsAndTerminalDenial(t *testing.T) {
	api := &fakeS3BucketDetails{head: &awss3.HeadBucketOutput{BucketRegion: aws.String("us-east-1")}, tags: &awss3.GetBucketTaggingOutput{TagSet: []s3types.Tag{{Key: aws.String(" team "), Value: aws.String("platform")}, {Key: aws.String(""), Value: aws.String("ignored")}}}}
	region, tags, err := readS3BucketDetails(context.Background(), api, "assets", "123456789012")
	if err != nil || region != "us-east-1" || tags["team"] != "platform" || len(tags) != 1 || api.headOwner != "123456789012" || api.tagOwner != "123456789012" {
		t.Fatalf("region=%q tags=%v owners=%q,%q err=%v", region, tags, api.headOwner, api.tagOwner, err)
	}
	api.tagsErr = &smithy.GenericAPIError{Code: "NoSuchTagSet"}
	_, tags, err = readS3BucketDetails(context.Background(), api, "assets", "123456789012")
	if err != nil || len(tags) != 0 {
		t.Fatalf("missing tags: tags=%v err=%v", tags, err)
	}
	api.tagsErr = &smithy.GenericAPIError{Code: "AccessDenied"}
	_, _, err = readS3BucketDetails(context.Background(), api, "assets", "123456789012")
	if err == nil || !errors.Is(err, api.tagsErr) {
		t.Fatalf("tag denial: %v", err)
	}
}

func TestS3BucketRecordBindsReportedIdentity(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	bucket := s3types.Bucket{Name: aws.String("assets"), BucketRegion: aws.String("us-east-1"), CreationDate: &created}
	got, err := s3BucketRecord(bucket, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "arn:aws:s3:::assets" || got.Resource == nil {
		t.Fatalf("bucket identity: %+v", got)
	}
	if got.Resource.ResourceID != got.ID || got.Resource.ResourceType != "aws_s3_bucket" || got.Resource.SourceRecordID != got.ID {
		t.Fatalf("typed identity: %+v", got.Resource)
	}
	if got.Resource.Attributes["bucket_region"] != "us-east-1" || got.Resource.Attributes["creation_time"] != created {
		t.Fatalf("reported fields: %+v", got.Resource.Attributes)
	}
	if _, ok := got.Resource.Attributes["default_encryption_algorithms"]; ok {
		t.Fatal("invented encryption evidence")
	}
}

func TestS3DiscoveryUsesRegionalBoundary(t *testing.T) {
	input, err := s3ListInput("us-gov-west-1")
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(input.BucketRegion) != "us-gov-west-1" || aws.ToInt32(input.MaxBuckets) != s3ListPageLimit {
		t.Fatalf("ListBuckets input = %+v", input)
	}
	bucket := s3types.Bucket{Name: aws.String("assets"), BucketRegion: aws.String("us-gov-west-1")}
	got, err := s3BucketRecord(bucket, "us-gov-west-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws-us-gov"})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "arn:aws-us-gov:s3:::assets" || got.Resource == nil || got.Resource.ARN != got.ID {
		t.Fatalf("partition-aware bucket: %+v", got)
	}
	if _, err := s3BucketRecord(bucket, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}); err == nil {
		t.Fatal("out-of-scope bucket region accepted")
	}
	if _, err := s3ListInput("aws-global"); err == nil {
		t.Fatal("global S3 claim accepted")
	}
}

func TestS3CollectsEveryConfiguredRegion(t *testing.T) {
	calls := map[string]int{}
	fake := Collector{
		LoadConfig: func(_ context.Context, region string) (aws.Config, error) { return aws.Config{Region: region}, nil },
		VerifyIdentity: func(_ context.Context, _ aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{"s3": func(_ context.Context, cfg aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
			calls[cfg.Region]++
			return []collector.Record{{ID: cfg.Region + "/bucket", Name: "bucket"}}, nil
		}},
	}
	outcome, err := fake.CollectReport(context.Background(), Config{AccountID: "123456789012", Regions: []string{"us-east-1", "us-west-2"}, Services: []string{"s3"}})
	if err != nil {
		t.Fatal(err)
	}
	if calls["us-east-1"] != 1 || calls["us-west-2"] != 1 || len(outcome.Report.Records) != 2 {
		t.Fatalf("calls=%v records=%d", calls, len(outcome.Report.Records))
	}
}

func TestS3BucketRecordPreservesUnknownCreationTime(t *testing.T) {
	bucket := s3types.Bucket{Name: aws.String("assets")}
	got, err := s3BucketRecord(bucket, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	value, ok := got.Resource.Attributes["creation_time"]
	if !ok || value != nil {
		t.Fatalf("creation_time = %v, present=%t; want explicit null", value, ok)
	}
	zero := time.Time{}
	bucket.CreationDate = &zero
	got, err = s3BucketRecord(bucket, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	value, ok = got.Resource.Attributes["creation_time"]
	if !ok || value != nil {
		t.Fatalf("zero creation_time = %v, present=%t; want explicit null", value, ok)
	}
}
