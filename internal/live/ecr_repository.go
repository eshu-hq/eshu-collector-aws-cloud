// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// ecrRepositoryRecord keeps the existing placeholder and adds the repository
// observation reported by DescribeRepositories and ListTagsForResource.
func ecrRepositoryRecord(repository ecrtypes.Repository, tags []ecrtypes.Tag, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(repository.RepositoryArn))
	name := aws.ToString(repository.RepositoryName)
	uri := strings.TrimSpace(aws.ToString(repository.RepositoryUri))
	result := record(arn, "ecr", region, name, "repository")
	id := firstECRIdentity(arn, uri, name)
	attrs := map[string]any{
		"created_at":           nil,
		"encryption_type":      "",
		"image_tag_mutability": strings.TrimSpace(string(repository.ImageTagMutability)),
		"kms_key":              "",
		"repository_uri":       uri,
		"scan_on_push":         false,
	}
	if repository.CreatedAt != nil && !repository.CreatedAt.IsZero() {
		attrs["created_at"] = repository.CreatedAt.UTC()
	}
	if repository.EncryptionConfiguration != nil {
		attrs["encryption_type"] = strings.TrimSpace(string(repository.EncryptionConfiguration.EncryptionType))
		attrs["kms_key"] = strings.TrimSpace(aws.ToString(repository.EncryptionConfiguration.KmsKey))
	}
	if repository.ImageScanningConfiguration != nil {
		attrs["scan_on_push"] = repository.ImageScanningConfiguration.ScanOnPush
	}
	result.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "ecr", ResourceType: "aws_ecr_repository",
		ResourceID: id, ARN: arn, Name: name, Tags: ecrTags(tags), Attributes: attrs,
		CorrelationAnchors: []string{arn, uri, name}, SourceRecordID: firstECRIdentity(arn, name),
	}
	return result
}

func firstECRIdentity(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func ecrTags(tags []ecrtypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	mapped := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(aws.ToString(tag.Key)); key != "" {
			mapped[key] = aws.ToString(tag.Value)
		}
	}
	return mapped
}
