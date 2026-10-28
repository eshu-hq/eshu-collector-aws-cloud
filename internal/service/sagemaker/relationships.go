// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package sagemaker

import (
	"strings"

	awscloud "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

// modelArtifactRelationship maps an `s3://bucket/key` model-artifact URL to an
// S3 bucket relationship target, keeping the raw URL and key prefix as
// attributes. It returns ok=false for blank, non-S3, or duplicate URLs.
func modelArtifactRelationship(
	modelID, modelARN, modelDataURL string,
	seen map[string]struct{},
) (awscloud.RelationshipObservation, bool) {
	artifact := strings.TrimSpace(modelDataURL)
	if artifact == "" {
		return awscloud.RelationshipObservation{}, false
	}
	if _, ok := seen[artifact]; ok {
		return awscloud.RelationshipObservation{}, false
	}
	seen[artifact] = struct{}{}
	bucket, key, ok := parseS3URL(artifact)
	if !ok {
		return awscloud.RelationshipObservation{}, false
	}
	bucketARN := "arn:" + awscloud.PartitionFromARN(modelARN) + ":s3:::" + bucket
	attributes := map[string]any{"model_data_url": artifact, "bucket": bucket}
	if key != "" {
		attributes["object_key"] = key
	}
	return awscloud.RelationshipObservation{
		RelationshipType: catalog.RelationshipSageMakerModelUsesS3Artifact,
		SourceResourceID: modelID,
		SourceARN:        strings.TrimSpace(modelARN),
		TargetResourceID: bucketARN,
		TargetARN:        bucketARN,
		TargetType:       catalog.ResourceTypeS3Bucket,
		Attributes:       attributes,
		SourceRecordID:   modelID + "#artifact#" + artifact,
	}, true
}

// parseS3URL splits an `s3://bucket[/key]` URL into the bucket name and
// optional object key. It returns ok=false when the input is not an `s3://`
// URL or carries no bucket segment.
func parseS3URL(url string) (bucket string, key string, ok bool) {
	trimmed := strings.TrimSpace(url)
	if !strings.HasPrefix(trimmed, "s3://") {
		return "", "", false
	}
	remainder := strings.TrimPrefix(trimmed, "s3://")
	if remainder == "" {
		return "", "", false
	}
	bucket, key, _ = strings.Cut(remainder, "/")
	bucket = strings.TrimSpace(bucket)
	if bucket == "" {
		return "", "", false
	}
	return bucket, strings.TrimSpace(key), true
}
