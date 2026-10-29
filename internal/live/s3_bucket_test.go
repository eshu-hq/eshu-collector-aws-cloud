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
	buckets         *awss3.ListBucketsOutput
	listErr         error
	head            *awss3.HeadBucketOutput
	tags            *awss3.GetBucketTaggingOutput
	encryption      *awss3.GetBucketEncryptionOutput
	versioning      *awss3.GetBucketVersioningOutput
	publicAccess    *awss3.GetPublicAccessBlockOutput
	policyStatus    *awss3.GetBucketPolicyStatusOutput
	ownership       *awss3.GetBucketOwnershipControlsOutput
	headErr         error
	tagsErr         error
	encryptionErr   error
	versioningErr   error
	publicAccessErr error
	policyErr       error
	ownershipErr    error
	headOwner       string
	tagOwner        string
	encryptionOwner string
	versioningOwner string
	publicOwner     string
	policyOwner     string
	ownershipOwner  string
}

func (f *fakeS3BucketDetails) ListBuckets(_ context.Context, _ *awss3.ListBucketsInput, _ ...func(*awss3.Options)) (*awss3.ListBucketsOutput, error) {
	return f.buckets, f.listErr
}

func (f *fakeS3BucketDetails) HeadBucket(_ context.Context, input *awss3.HeadBucketInput, _ ...func(*awss3.Options)) (*awss3.HeadBucketOutput, error) {
	f.headOwner = aws.ToString(input.ExpectedBucketOwner)
	return f.head, f.headErr
}

func (f *fakeS3BucketDetails) GetBucketTagging(_ context.Context, input *awss3.GetBucketTaggingInput, _ ...func(*awss3.Options)) (*awss3.GetBucketTaggingOutput, error) {
	f.tagOwner = aws.ToString(input.ExpectedBucketOwner)
	return f.tags, f.tagsErr
}

func (f *fakeS3BucketDetails) GetBucketEncryption(_ context.Context, input *awss3.GetBucketEncryptionInput, _ ...func(*awss3.Options)) (*awss3.GetBucketEncryptionOutput, error) {
	f.encryptionOwner = aws.ToString(input.ExpectedBucketOwner)
	return f.encryption, f.encryptionErr
}

func (f *fakeS3BucketDetails) GetBucketVersioning(_ context.Context, input *awss3.GetBucketVersioningInput, _ ...func(*awss3.Options)) (*awss3.GetBucketVersioningOutput, error) {
	f.versioningOwner = aws.ToString(input.ExpectedBucketOwner)
	return f.versioning, f.versioningErr
}

func (f *fakeS3BucketDetails) GetPublicAccessBlock(_ context.Context, input *awss3.GetPublicAccessBlockInput, _ ...func(*awss3.Options)) (*awss3.GetPublicAccessBlockOutput, error) {
	f.publicOwner = aws.ToString(input.ExpectedBucketOwner)
	return f.publicAccess, f.publicAccessErr
}

func (f *fakeS3BucketDetails) GetBucketPolicyStatus(_ context.Context, input *awss3.GetBucketPolicyStatusInput, _ ...func(*awss3.Options)) (*awss3.GetBucketPolicyStatusOutput, error) {
	f.policyOwner = aws.ToString(input.ExpectedBucketOwner)
	return f.policyStatus, f.policyErr
}

func (f *fakeS3BucketDetails) GetBucketOwnershipControls(_ context.Context, input *awss3.GetBucketOwnershipControlsInput, _ ...func(*awss3.Options)) (*awss3.GetBucketOwnershipControlsOutput, error) {
	f.ownershipOwner = aws.ToString(input.ExpectedBucketOwner)
	return f.ownership, f.ownershipErr
}

func TestS3PolicyAndOwnershipMetadata(t *testing.T) {
	api := &fakeS3BucketDetails{
		policyStatus: &awss3.GetBucketPolicyStatusOutput{PolicyStatus: &s3types.PolicyStatus{IsPublic: aws.Bool(false)}},
		ownership:    &awss3.GetBucketOwnershipControlsOutput{OwnershipControls: &s3types.OwnershipControls{Rules: []s3types.OwnershipControlsRule{{ObjectOwnership: s3types.ObjectOwnershipBucketOwnerEnforced}}}},
	}
	attrs, err := readS3PolicyAndOwnership(context.Background(), api, "assets", "123456789012")
	if err != nil || attrs["policy_is_public"] != false || attrs["ownership_controls"].([]string)[0] != "BucketOwnerEnforced" || api.policyOwner != "123456789012" || api.ownershipOwner != "123456789012" {
		t.Fatalf("attrs=%v policyOwner=%q ownershipOwner=%q err=%v", attrs, api.policyOwner, api.ownershipOwner, err)
	}
	api.policyErr = &smithy.GenericAPIError{Code: "NoSuchBucketPolicy"}
	api.ownershipErr = &smithy.GenericAPIError{Code: "OwnershipControlsNotFoundError"}
	attrs, err = readS3PolicyAndOwnership(context.Background(), api, "assets", "123456789012")
	if err != nil || attrs["policy_is_public"] != nil || attrs["ownership_controls"] != nil {
		t.Fatalf("missing configuration: attrs=%v err=%v", attrs, err)
	}
	api.policyErr = nil
	api.policyStatus = &awss3.GetBucketPolicyStatusOutput{PolicyStatus: &s3types.PolicyStatus{}}
	api.ownershipErr = nil
	api.ownership = &awss3.GetBucketOwnershipControlsOutput{OwnershipControls: &s3types.OwnershipControls{Rules: []s3types.OwnershipControlsRule{{}, {ObjectOwnership: "  "}}}}
	attrs, err = readS3PolicyAndOwnership(context.Background(), api, "assets", "123456789012")
	if err != nil || attrs["policy_is_public"] != nil || attrs["ownership_controls"] != nil {
		t.Fatalf("empty reported values: attrs=%v err=%v", attrs, err)
	}
	api.policyErr = &smithy.GenericAPIError{Code: "AccessDenied"}
	_, err = readS3PolicyAndOwnership(context.Background(), api, "assets", "123456789012")
	if !errors.Is(err, api.policyErr) {
		t.Fatalf("policy denial: %v", err)
	}
	api.policyErr = nil
	api.ownershipErr = &smithy.GenericAPIError{Code: "AccessDenied"}
	_, err = readS3PolicyAndOwnership(context.Background(), api, "assets", "123456789012")
	if !errors.Is(err, api.ownershipErr) {
		t.Fatalf("ownership denial: %v", err)
	}
}

func TestS3BucketPostureReadsPreserveMissingAndDenial(t *testing.T) {
	api := &fakeS3BucketDetails{
		buckets:         &awss3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: aws.String("assets"), BucketRegion: aws.String("us-east-1")}}},
		head:            &awss3.HeadBucketOutput{BucketRegion: aws.String("us-east-1")},
		versioning:      &awss3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatusEnabled, MFADelete: s3types.MFADeleteStatusDisabled},
		publicAccessErr: &smithy.GenericAPIError{Code: "NoSuchPublicAccessBlockConfiguration"},
	}
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	rows, err := listS3WithAPI(context.Background(), api, "us-east-1", identity)
	if err != nil || len(rows) != 1 || api.versioningOwner != identity.AccountID || api.publicOwner != identity.AccountID {
		t.Fatalf("rows=%v owners=%q,%q err=%v", rows, api.versioningOwner, api.publicOwner, err)
	}
	attrs := rows[0].Resource.Attributes
	if attrs["versioning_status"] != "Enabled" || attrs["mfa_delete"] != "Disabled" {
		t.Fatalf("versioning: %v", attrs)
	}
	for _, key := range []string{"block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"} {
		if value, ok := attrs[key]; !ok || value != nil {
			t.Fatalf("missing public access configuration %q = %v, present=%t", key, value, ok)
		}
	}
	api.publicAccessErr = nil
	api.publicAccess = &awss3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls: aws.Bool(true), IgnorePublicAcls: aws.Bool(false),
		BlockPublicPolicy: aws.Bool(true), RestrictPublicBuckets: aws.Bool(true),
	}}
	rows, err = listS3WithAPI(context.Background(), api, "us-east-1", identity)
	if err != nil || len(rows) != 1 {
		t.Fatalf("configured public access: rows=%v err=%v", rows, err)
	}
	attrs = rows[0].Resource.Attributes
	if attrs["block_public_acls"] != true || attrs["ignore_public_acls"] != false || attrs["block_public_policy"] != true || attrs["restrict_public_buckets"] != true {
		t.Fatalf("configured public access flags: %v", attrs)
	}
	api.publicAccessErr = &smithy.GenericAPIError{Code: "AccessDenied"}
	_, err = listS3WithAPI(context.Background(), api, "us-east-1", identity)
	if !errors.Is(err, api.publicAccessErr) {
		t.Fatalf("public access denial: %v", err)
	}
}

func TestS3EncryptionReadKeepsDeniedStateUnknown(t *testing.T) {
	api := &fakeS3BucketDetails{encryptionErr: &smithy.GenericAPIError{Code: "AccessDenied"}}
	attrs, denied, err := readS3BucketEncryption(context.Background(), api, "assets", "123456789012")
	if err != nil || !denied || len(attrs) != 0 || api.encryptionOwner != "123456789012" {
		t.Fatalf("attrs=%v denied=%t owner=%q err=%v", attrs, denied, api.encryptionOwner, err)
	}
	api.encryptionErr = &smithy.GenericAPIError{Code: "ServerSideEncryptionConfigurationNotFoundError"}
	attrs, denied, err = readS3BucketEncryption(context.Background(), api, "assets", "123456789012")
	if err != nil || denied || len(attrs["default_encryption_algorithms"].([]string)) != 0 || attrs["bucket_key_enabled"] != false {
		t.Fatalf("missing configuration: attrs=%v denied=%t err=%v", attrs, denied, err)
	}
	api.encryptionErr = &smithy.GenericAPIError{Code: "ThrottlingException"}
	_, denied, err = readS3BucketEncryption(context.Background(), api, "assets", "123456789012")
	if !errors.Is(err, api.encryptionErr) || denied {
		t.Fatalf("non-denial: denied=%t err=%v", denied, err)
	}
}

func TestS3EncryptionReadMapsReportedRules(t *testing.T) {
	api := &fakeS3BucketDetails{encryption: &awss3.GetBucketEncryptionOutput{
		ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{Rules: []s3types.ServerSideEncryptionRule{
			{ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAes256}},
			{ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAwsKms, KMSMasterKeyID: aws.String("alias/team")}, BucketKeyEnabled: aws.Bool(true)},
		}},
	}}
	attrs, denied, err := readS3BucketEncryption(context.Background(), api, "assets", "123456789012")
	if err != nil || denied {
		t.Fatalf("denied=%t err=%v", denied, err)
	}
	algorithms := attrs["default_encryption_algorithms"].([]string)
	keys := attrs["kms_master_key_ids"].([]string)
	if len(algorithms) != 2 || algorithms[0] != "AES256" || algorithms[1] != "aws:kms" || len(keys) != 1 || keys[0] != "alias/team" || attrs["bucket_key_enabled"] != true {
		t.Fatalf("encryption attributes: %v", attrs)
	}
}

func TestS3OptionalEncryptionDenialsKeepBucketsAndDistinctWarnings(t *testing.T) {
	api := &fakeS3BucketDetails{
		buckets: &awss3.ListBucketsOutput{Buckets: []s3types.Bucket{
			{Name: aws.String("assets"), BucketRegion: aws.String("us-east-1")},
			{Name: aws.String("archives"), BucketRegion: aws.String("us-east-1")},
		}},
		head:          &awss3.HeadBucketOutput{BucketRegion: aws.String("us-east-1")},
		encryptionErr: &smithy.GenericAPIError{Code: "AccessDenied"},
	}
	records, err := listS3WithAPI(context.Background(), api, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	var denied *optionalReadDenied
	if !errors.As(err, &denied) || len(denied.denials) != 2 || len(records) != 2 {
		t.Fatalf("records=%v denials=%+v err=%v", records, denied, err)
	}
	if denied.denials[0].resource != "bucket:assets" || denied.denials[1].resource != "bucket:archives" {
		t.Fatalf("warning resources: %+v", denied.denials)
	}
	for _, row := range records {
		if row.Resource == nil || row.Resource.ResourceID == "" || row.Resource.Attributes["bucket_region"] != "us-east-1" {
			t.Fatalf("lost core bucket evidence: %+v", row)
		}
		if _, present := row.Resource.Attributes["versioning_status"]; !present || row.Resource.Attributes["block_public_acls"] != nil {
			t.Fatalf("encryption denial lost or invented bucket posture: %+v", row.Resource.Attributes)
		}
		if _, present := row.Resource.Attributes["default_encryption_algorithms"]; present {
			t.Fatalf("denied encryption presented as known: %+v", row.Resource.Attributes)
		}
	}
	collectorWithS3 := Collector{
		LoadConfig: func(_ context.Context, region string) (aws.Config, error) { return aws.Config{Region: region}, nil },
		VerifyIdentity: func(_ context.Context, _ aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{"s3": func(ctx context.Context, cfg aws.Config, identity VerifiedIdentity) ([]collector.Record, error) {
			return listS3WithAPI(ctx, api, cfg.Region, identity)
		}},
	}
	outcome, err := collectorWithS3.CollectReport(context.Background(), Config{AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"s3"}})
	if err != nil || len(outcome.Resources) != 2 || len(outcome.WarningObservations) != 2 || len(outcome.Warnings) != 1 {
		t.Fatalf("partial S3 outcome: resources=%d warnings=%d statuses=%v err=%v", len(outcome.Resources), len(outcome.WarningObservations), outcome.Warnings, err)
	}
	for _, warning := range outcome.WarningObservations {
		if warning.Attributes["operation"] != "GetBucketEncryption" || warning.Attributes["effect"] != "encryption-unknown" {
			t.Fatalf("warning identity: %+v", warning)
		}
	}
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
