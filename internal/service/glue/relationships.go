// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package glue

import (
	"strings"

	awscloud "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

func tableS3LocationRelationship(boundary awscloud.Boundary, table Table) *awscloud.RelationshipObservation {
	location := strings.TrimSpace(table.StorageLocation)
	bucket, prefix, ok := parseS3Location(location)
	if !ok {
		return nil
	}
	tableID := tableResourceID(table)
	if tableID == "" {
		return nil
	}
	bucketARN := "arn:" + awscloud.PartitionForBoundary(boundary) + ":s3:::" + bucket
	attributes := map[string]any{
		"storage_location": location,
		"bucket":           bucket,
	}
	if prefix != "" {
		attributes["object_key_prefix"] = prefix
	}
	return &awscloud.RelationshipObservation{
		Boundary:         boundary,
		RelationshipType: catalog.RelationshipGlueTableStoredAtS3Location,
		SourceResourceID: tableID,
		TargetResourceID: bucketARN,
		TargetARN:        bucketARN,
		TargetType:       catalog.ResourceTypeS3Bucket,
		Attributes:       attributes,
		SourceRecordID:   tableID + "->" + catalog.RelationshipGlueTableStoredAtS3Location + ":" + bucketARN,
	}
}

// parseS3Location splits an `s3://bucket[/key]` URI into the bucket name and
// optional object-key prefix. It returns ok=false when the input is not an
// `s3://` URI or has no bucket segment so the caller can skip emission.
func parseS3Location(location string) (bucket string, prefix string, ok bool) {
	trimmed := strings.TrimSpace(location)
	if !strings.HasPrefix(trimmed, "s3://") {
		return "", "", false
	}
	remainder := strings.TrimPrefix(trimmed, "s3://")
	if remainder == "" {
		return "", "", false
	}
	slash := strings.IndexByte(remainder, '/')
	if slash < 0 {
		bucket = strings.TrimSpace(remainder)
		return bucket, "", bucket != ""
	}
	bucket = strings.TrimSpace(remainder[:slash])
	if bucket == "" {
		return "", "", false
	}
	prefix = strings.TrimSpace(remainder[slash+1:])
	return bucket, prefix, true
}

func tableResourceID(table Table) string {
	databaseName := strings.TrimSpace(table.DatabaseName)
	name := strings.TrimSpace(table.Name)
	switch {
	case databaseName != "" && name != "":
		return databaseName + "/" + name
	case name != "":
		return name
	default:
		return ""
	}
}
