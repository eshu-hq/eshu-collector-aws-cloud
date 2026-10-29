// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

const s3ListPageLimit int32 = 10000

// s3ListInput restricts bucket discovery to the claim region, as the legacy
// scanner does. S3 returns an account-wide list without this filter.
func s3ListInput(region string) (*awss3.ListBucketsInput, error) {
	region = strings.TrimSpace(region)
	if region == "" || region == "aws-global" {
		return nil, fmt.Errorf("s3 bucket discovery requires a regional claim")
	}
	return &awss3.ListBucketsInput{BucketRegion: aws.String(region), MaxBuckets: aws.Int32(s3ListPageLimit)}, nil
}

// s3BucketRecord emits only fields in ListBuckets. Other S3 metadata needs
// separate control-plane reads and must not be inferred from absent values.
func s3BucketRecord(bucket s3types.Bucket, region string, identity VerifiedIdentity) (collector.Record, error) {
	name := strings.TrimSpace(aws.ToString(bucket.Name))
	if name == "" {
		return collector.Record{}, fmt.Errorf("s3 ListBuckets returned a bucket without a name")
	}
	reportedRegion := strings.TrimSpace(aws.ToString(bucket.BucketRegion))
	if reportedRegion != "" && reportedRegion != region {
		return collector.Record{}, fmt.Errorf("s3 ListBuckets returned a bucket outside the claimed region")
	}
	if reportedRegion == "" {
		reportedRegion = region
	}
	arn := "arn:" + identity.Partition + ":s3:::" + name
	result := record(arn, "s3", region, name, "bucket")
	attrs := map[string]any{"bucket_region": reportedRegion, "creation_time": nil}
	if bucket.CreationDate != nil && !bucket.CreationDate.IsZero() {
		attrs["creation_time"] = bucket.CreationDate.UTC()
	}
	result.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "s3", ResourceType: "aws_s3_bucket",
		ResourceID: arn, ARN: arn, Name: name, Attributes: attrs,
		CorrelationAnchors: []string{arn, name, "s3://" + name}, SourceRecordID: arn,
	}
	return result, nil
}
