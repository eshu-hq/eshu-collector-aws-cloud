// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

// s3StringAttr reads one string attribute from a bucket metadata map. A
// missing or non-string value reads as empty so callers keep the in-tree
// absent-means-unset semantics.
func s3StringAttr(attrs map[string]any, key string) string {
	raw, present := attrs[key]
	if !present {
		return ""
	}
	value, isString := raw.(string)
	if !isString {
		return ""
	}
	return strings.TrimSpace(value)
}

// s3LoggingRelationship maps one bucket's server-access-log target into a
// typed bucket->bucket edge. It mirrors the in-tree loggingRelationship
// derivation: no target bucket means no edge, and the target ARN is
// synthesized with the claim partition because S3 has no API ARN to report.
// The raw logging configuration never leaves the caller.
func s3LoggingRelationship(region, sourceARN, targetName, targetPrefix, partition string) (collector.LiveRelationship, bool) {
	sourceARN = strings.TrimSpace(sourceARN)
	targetName = strings.TrimSpace(targetName)
	partition = strings.TrimSpace(partition)
	if sourceARN == "" || targetName == "" || partition == "" {
		return collector.LiveRelationship{}, false
	}
	targetARN := "arn:" + partition + ":s3:::" + targetName
	return collector.LiveRelationship{
		Region:           strings.TrimSpace(region),
		ServiceKind:      catalog.ServiceS3,
		RelationshipType: catalog.RelationshipS3BucketLogsToBucket,
		SourceResourceID: sourceARN,
		SourceARN:        sourceARN,
		TargetResourceID: targetARN,
		TargetARN:        targetARN,
		TargetType:       catalog.ResourceTypeS3Bucket,
		SourceRecordID:   sourceARN + "->logging:" + targetName,
		Attributes: map[string]any{
			"target_prefix": strings.TrimSpace(targetPrefix),
		},
	}, true
}
