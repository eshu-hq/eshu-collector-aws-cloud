// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

func TestECRRepositoryRecordRetainsLegacyObservation(t *testing.T) {
	created := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	repository := ecrtypes.Repository{
		RepositoryArn:  aws.String("arn:aws:ecr:us-east-1:123456789012:repository/demo"),
		RepositoryName: aws.String("demo"), RepositoryUri: aws.String("123456789012.dkr.ecr.us-east-1.amazonaws.com/demo"),
		RegistryId: aws.String("123456789012"), CreatedAt: &created,
		ImageTagMutability:         ecrtypes.ImageTagMutabilityImmutable,
		EncryptionConfiguration:    &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionTypeKms, KmsKey: aws.String("key-123")},
		ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{ScanOnPush: true},
	}
	got := ecrRepositoryRecord(repository, []ecrtypes.Tag{{Key: aws.String("team"), Value: aws.String("platform")}}, "us-east-1")
	if got.Resource == nil {
		t.Fatal("typed ECR repository missing")
	}
	resource := got.Resource
	if resource.ResourceType != "aws_ecr_repository" || resource.ResourceID != aws.ToString(repository.RepositoryArn) || resource.ARN != resource.ResourceID || resource.Name != "demo" {
		t.Fatalf("repository identity = %+v", resource)
	}
	if resource.Tags["team"] != "platform" || resource.Attributes["kms_key"] != "key-123" || resource.Attributes["scan_on_push"] != true || resource.Attributes["created_at"] != created {
		t.Fatalf("repository attributes = %#v, tags = %#v", resource.Attributes, resource.Tags)
	}
	if len(resource.CorrelationAnchors) != 3 || resource.CorrelationAnchors[1] != aws.ToString(repository.RepositoryUri) {
		t.Fatalf("repository anchors = %#v", resource.CorrelationAnchors)
	}
	if got.ID != aws.ToString(repository.RepositoryArn) || got.Name != "demo" {
		t.Fatalf("placeholder identity changed: %+v", got)
	}
	if resource.SourceRecordID != aws.ToString(repository.RepositoryArn) {
		t.Fatalf("repository source record = %q", resource.SourceRecordID)
	}
	withoutARN := repository
	withoutARN.RepositoryArn = nil
	fallback := ecrRepositoryRecord(withoutARN, nil, "us-east-1")
	if fallback.Resource.ResourceID != aws.ToString(repository.RepositoryUri) || fallback.Resource.SourceRecordID != "demo" {
		t.Fatalf("repository fallback identity = %+v", fallback.Resource)
	}
}
