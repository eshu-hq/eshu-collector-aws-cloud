// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package bedrock

import (
	"strings"

	awscloud "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

func knowledgeBaseRelationships(kb KnowledgeBase) []awscloud.RelationshipObservation {
	id := firstNonEmpty(kb.ARN, kb.ID, kb.Name)
	if id == "" {
		return nil
	}
	partition := awscloud.PartitionFromARN(kb.ARN)
	var observations []awscloud.RelationshipObservation
	for _, source := range kb.DataSources {
		if observation, ok := knowledgeBaseDataSourceRelationship(id, kb.ARN, partition, source); ok {
			observations = append(observations, observation)
		}
	}
	return observations
}

// knowledgeBaseDataSourceRelationship maps one knowledge base data source to a
// typed relationship target. S3 sources resolve to an S3 bucket ARN; Confluence,
// SharePoint, and web-crawler sources carry their host/site/seed URL as the
// target reference. It returns ok=false for unaddressable sources.
func knowledgeBaseDataSourceRelationship(
	kbID, kbARN, partition string,
	source KnowledgeBaseDataSource,
) (awscloud.RelationshipObservation, bool) {
	attributes := map[string]any{"data_source_type": strings.TrimSpace(source.Type)}
	if name := strings.TrimSpace(source.Name); name != "" {
		attributes["data_source_name"] = name
	}
	if dsID := strings.TrimSpace(source.ID); dsID != "" {
		attributes["data_source_id"] = dsID
	}
	if bucketArg := strings.TrimSpace(source.S3BucketARN); bucketArg != "" {
		bucketARN, ok := normalizeS3BucketARN(partition, bucketArg)
		if !ok {
			// A reported S3 reference that resolves to an empty bucket name (for
			// example an `s3://` or `s3:///path` scheme prefix) cannot address a
			// real bucket. Dropping the edge keeps an invalid empty join key out
			// of the graph rather than emitting `arn:<partition>:s3:::`.
			return awscloud.RelationshipObservation{}, false
		}
		return awscloud.RelationshipObservation{
			RelationshipType: catalog.RelationshipBedrockKnowledgeBaseUsesS3DataSource,
			SourceResourceID: kbID,
			SourceARN:        strings.TrimSpace(kbARN),
			TargetResourceID: bucketARN,
			TargetARN:        bucketARN,
			TargetType:       catalog.ResourceTypeS3Bucket,
			Attributes:       attributes,
			SourceRecordID:   kbID + "#s3-data-source#" + bucketARN,
		}, true
	}
	url := strings.TrimSpace(source.URL)
	if url == "" {
		return awscloud.RelationshipObservation{}, false
	}
	relationshipType, targetType, ok := urlDataSourceKinds(source.Type)
	if !ok {
		return awscloud.RelationshipObservation{}, false
	}
	attributes["url"] = url
	return awscloud.RelationshipObservation{
		RelationshipType: relationshipType,
		SourceResourceID: kbID,
		SourceARN:        strings.TrimSpace(kbARN),
		TargetResourceID: url,
		TargetType:       targetType,
		Attributes:       attributes,
		SourceRecordID:   kbID + "#" + targetType + "#" + url,
	}, true
}

// urlDataSourceKinds maps a connector type to its relationship and external
// target type for URL-addressed sources. It returns ok=false for connector
// types that are not URL-addressed.
func urlDataSourceKinds(dataSourceType string) (relationshipType, targetType string, ok bool) {
	switch strings.ToUpper(strings.TrimSpace(dataSourceType)) {
	case "CONFLUENCE":
		return catalog.RelationshipBedrockKnowledgeBaseUsesConfluence, "confluence_data_source", true
	case "SHAREPOINT":
		return catalog.RelationshipBedrockKnowledgeBaseUsesSharePoint, "sharepoint_data_source", true
	case "WEB":
		return catalog.RelationshipBedrockKnowledgeBaseUsesWebCrawler, "web_data_source", true
	default:
		return "", "", false
	}
}

// normalizeS3BucketARN resolves an S3 data-source reference to a bucket ARN,
// reporting ok=false when no bucket can be determined. It returns bucketArg
// unchanged when it is already an S3 bucket ARN, otherwise it synthesizes one
// from the partition and a bare bucket name. Bedrock reports a BucketArn for S3
// data sources, so the ARN branch is the common case; the name branch guards
// against any bare-name or `s3://` URL input. A non-ARN input that yields an
// empty bucket after trimming the scheme and path (for example `s3://` or
// `s3:///path`) is unresolvable, so it returns ""/ok=false instead of
// synthesizing an invalid `arn:<partition>:s3:::` with an empty join key.
func normalizeS3BucketARN(partition, bucketArg string) (string, bool) {
	if strings.HasPrefix(bucketArg, "arn:") {
		return bucketArg, true
	}
	bucket := strings.TrimPrefix(bucketArg, "s3://")
	bucket, _, _ = strings.Cut(bucket, "/")
	bucket = strings.TrimSpace(bucket)
	if bucket == "" {
		return "", false
	}
	return s3BucketARN(partition, bucket), true
}
