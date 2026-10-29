// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

const s3ListPageLimit int32 = 10000

type s3BucketDetailsAPI interface {
	HeadBucket(context.Context, *awss3.HeadBucketInput, ...func(*awss3.Options)) (*awss3.HeadBucketOutput, error)
	GetBucketTagging(context.Context, *awss3.GetBucketTaggingInput, ...func(*awss3.Options)) (*awss3.GetBucketTaggingOutput, error)
	GetBucketEncryption(context.Context, *awss3.GetBucketEncryptionInput, ...func(*awss3.Options)) (*awss3.GetBucketEncryptionOutput, error)
	GetBucketVersioning(context.Context, *awss3.GetBucketVersioningInput, ...func(*awss3.Options)) (*awss3.GetBucketVersioningOutput, error)
	GetPublicAccessBlock(context.Context, *awss3.GetPublicAccessBlockInput, ...func(*awss3.Options)) (*awss3.GetPublicAccessBlockOutput, error)
	GetBucketPolicyStatus(context.Context, *awss3.GetBucketPolicyStatusInput, ...func(*awss3.Options)) (*awss3.GetBucketPolicyStatusOutput, error)
	GetBucketOwnershipControls(context.Context, *awss3.GetBucketOwnershipControlsInput, ...func(*awss3.Options)) (*awss3.GetBucketOwnershipControlsOutput, error)
	GetBucketWebsite(context.Context, *awss3.GetBucketWebsiteInput, ...func(*awss3.Options)) (*awss3.GetBucketWebsiteOutput, error)
	GetBucketLogging(context.Context, *awss3.GetBucketLoggingInput, ...func(*awss3.Options)) (*awss3.GetBucketLoggingOutput, error)
	GetBucketReplication(context.Context, *awss3.GetBucketReplicationInput, ...func(*awss3.Options)) (*awss3.GetBucketReplicationOutput, error)
}

// readS3Replication reports only whether the returned configuration has rules.
// A missing configuration is known false; an empty successful response is unknown.
func readS3Replication(ctx context.Context, api s3BucketDetailsAPI, name, accountID string) (*bool, error) {
	output, err := api.GetBucketReplication(ctx, &awss3.GetBucketReplicationInput{
		Bucket: aws.String(name), ExpectedBucketOwner: aws.String(accountID),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ReplicationConfigurationNotFoundError" {
			absent := false
			return &absent, nil
		}
		return nil, fmt.Errorf("s3 get bucket replication %q: %w", name, err)
	}
	if output == nil || output.ReplicationConfiguration == nil {
		return nil, nil
	}
	present := len(output.ReplicationConfiguration.Rules) > 0
	return &present, nil
}

// readS3WebsiteLogging maps only the legacy metadata fields. A missing website
// configuration and an empty logging response are known disabled states;
// denied or otherwise failed reads abort the bucket inventory.
func readS3WebsiteLogging(ctx context.Context, api s3BucketDetailsAPI, name, accountID string) (map[string]any, error) {
	website, err := api.GetBucketWebsite(ctx, &awss3.GetBucketWebsiteInput{
		Bucket: aws.String(name), ExpectedBucketOwner: aws.String(accountID),
	})
	if err != nil {
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "NoSuchWebsiteConfiguration" {
			return nil, fmt.Errorf("s3 get bucket website %q: %w", name, err)
		}
		website = nil
	}
	logging, err := api.GetBucketLogging(ctx, &awss3.GetBucketLoggingInput{
		Bucket: aws.String(name), ExpectedBucketOwner: aws.String(accountID),
	})
	if err != nil {
		return nil, fmt.Errorf("s3 get bucket logging %q: %w", name, err)
	}
	attrs := map[string]any{
		"website_enabled":            website != nil,
		"website_has_index_document": website != nil && website.IndexDocument != nil,
		"website_has_error_document": website != nil && website.ErrorDocument != nil,
		"website_redirect_host_name": "",
		"website_routing_rule_count": 0,
		"logging_enabled":            logging != nil && logging.LoggingEnabled != nil,
		"logging_target_bucket":      "",
		"logging_target_prefix":      "",
	}
	if website != nil {
		if website.RedirectAllRequestsTo != nil {
			attrs["website_redirect_host_name"] = strings.TrimSpace(aws.ToString(website.RedirectAllRequestsTo.HostName))
		}
		attrs["website_routing_rule_count"] = len(website.RoutingRules)
	}
	if logging != nil && logging.LoggingEnabled != nil {
		attrs["logging_target_bucket"] = strings.TrimSpace(aws.ToString(logging.LoggingEnabled.TargetBucket))
		attrs["logging_target_prefix"] = strings.TrimSpace(aws.ToString(logging.LoggingEnabled.TargetPrefix))
	}
	return attrs, nil
}

// readS3BucketPosture returns only reported bucket-level settings. An absent
// public-access-block configuration has unknown flags; it is not four false
// flags. An access denial or any other unexpected error fails the S3 read.
func readS3BucketPosture(ctx context.Context, api s3BucketDetailsAPI, name, accountID string) (map[string]any, error) {
	versioning, err := api.GetBucketVersioning(ctx, &awss3.GetBucketVersioningInput{
		Bucket: aws.String(name), ExpectedBucketOwner: aws.String(accountID),
	})
	if err != nil {
		return nil, fmt.Errorf("s3 get bucket versioning %q: %w", name, err)
	}
	attrs := map[string]any{"versioning_status": "", "mfa_delete": ""}
	if versioning != nil {
		attrs["versioning_status"] = strings.TrimSpace(string(versioning.Status))
		attrs["mfa_delete"] = strings.TrimSpace(string(versioning.MFADelete))
	}
	block, err := api.GetPublicAccessBlock(ctx, &awss3.GetPublicAccessBlockInput{
		Bucket: aws.String(name), ExpectedBucketOwner: aws.String(accountID),
	})
	if err != nil {
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "NoSuchPublicAccessBlockConfiguration" {
			return nil, fmt.Errorf("s3 get public access block %q: %w", name, err)
		}
		block = nil
	}
	attrs["block_public_acls"] = nil
	attrs["ignore_public_acls"] = nil
	attrs["block_public_policy"] = nil
	attrs["restrict_public_buckets"] = nil
	if block != nil && block.PublicAccessBlockConfiguration != nil {
		config := block.PublicAccessBlockConfiguration
		attrs["block_public_acls"] = optionalS3Bool(config.BlockPublicAcls)
		attrs["ignore_public_acls"] = optionalS3Bool(config.IgnorePublicAcls)
		attrs["block_public_policy"] = optionalS3Bool(config.BlockPublicPolicy)
		attrs["restrict_public_buckets"] = optionalS3Bool(config.RestrictPublicBuckets)
	}
	return attrs, nil
}

func optionalS3Bool(value *bool) any {
	if value == nil {
		return nil
	}
	return *value
}

type s3BucketAPI interface {
	s3BucketDetailsAPI
	ListBuckets(context.Context, *awss3.ListBucketsInput, ...func(*awss3.Options)) (*awss3.ListBucketsOutput, error)
}

// readS3BucketEncryption retains the legacy known-empty interpretation only
// for S3's explicit missing-configuration response. A denied read contributes
// no encryption attributes, so it cannot be mistaken for an unencrypted bucket.
func readS3BucketEncryption(ctx context.Context, api s3BucketDetailsAPI, name, accountID string) (map[string]any, bool, error) {
	output, err := api.GetBucketEncryption(ctx, &awss3.GetBucketEncryptionInput{
		Bucket: aws.String(name), ExpectedBucketOwner: aws.String(accountID),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			switch apiErr.ErrorCode() {
			case "AccessDenied", "AccessDeniedException":
				return nil, true, nil
			case "ServerSideEncryptionConfigurationNotFoundError":
				output = nil
			default:
				return nil, false, fmt.Errorf("s3 get bucket encryption %q: %w", name, err)
			}
		} else {
			return nil, false, fmt.Errorf("s3 get bucket encryption %q: %w", name, err)
		}
	}
	var algorithms []string
	var keyIDs []string
	bucketKeyEnabled := false
	if output != nil && output.ServerSideEncryptionConfiguration != nil {
		for _, rule := range output.ServerSideEncryptionConfiguration.Rules {
			byDefault := rule.ApplyServerSideEncryptionByDefault
			if byDefault == nil {
				continue
			}
			if algorithm := strings.TrimSpace(string(byDefault.SSEAlgorithm)); algorithm != "" {
				algorithms = append(algorithms, algorithm)
			}
			if keyID := strings.TrimSpace(aws.ToString(byDefault.KMSMasterKeyID)); keyID != "" {
				keyIDs = append(keyIDs, keyID)
			}
			bucketKeyEnabled = bucketKeyEnabled || aws.ToBool(rule.BucketKeyEnabled)
		}
	}
	return map[string]any{
		"default_encryption_algorithms": algorithms,
		"kms_master_key_ids":            keyIDs,
		"bucket_key_enabled":            bucketKeyEnabled,
	}, false, nil
}

// readS3BucketDetails follows the legacy required HeadBucket read and tag
// read. Only NoSuchTagSet means that tagging was not configured; denials fail
// the S3 read.
func readS3BucketDetails(ctx context.Context, api s3BucketDetailsAPI, name, accountID string) (string, map[string]string, error) {
	head, err := api.HeadBucket(ctx, &awss3.HeadBucketInput{
		Bucket: aws.String(name), ExpectedBucketOwner: aws.String(accountID),
	})
	if err != nil {
		return "", nil, fmt.Errorf("s3 head bucket %q: %w", name, err)
	}
	region := ""
	if head != nil {
		region = strings.TrimSpace(aws.ToString(head.BucketRegion))
	}
	result, err := api.GetBucketTagging(ctx, &awss3.GetBucketTaggingInput{
		Bucket: aws.String(name), ExpectedBucketOwner: aws.String(accountID),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchTagSet" {
			return region, nil, nil
		}
		return "", nil, fmt.Errorf("s3 get bucket tagging %q: %w", name, err)
	}
	if result == nil {
		return region, nil, nil
	}
	tags := make(map[string]string, len(result.TagSet))
	for _, tag := range result.TagSet {
		key := strings.TrimSpace(aws.ToString(tag.Key))
		if key != "" {
			tags[key] = aws.ToString(tag.Value)
		}
	}
	if len(tags) == 0 {
		return region, nil, nil
	}
	return region, tags, nil
}

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
