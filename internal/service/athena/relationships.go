// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package athena

import (
	"strings"

	awscloud "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

func workGroupResultBucketRelationship(
	boundary awscloud.Boundary,
	workGroup WorkGroup,
) *awscloud.RelationshipObservation {
	bucketARN := outputBucketARN(awscloud.PartitionForBoundary(boundary), workGroup.OutputLocation)
	if bucketARN == "" {
		return nil
	}
	sourceID := strings.TrimSpace(workGroup.Name)
	if sourceID == "" {
		return nil
	}
	return &awscloud.RelationshipObservation{
		Boundary:         boundary,
		RelationshipType: catalog.RelationshipAthenaWorkGroupUsesResultBucket,
		SourceResourceID: sourceID,
		TargetResourceID: bucketARN,
		TargetARN:        bucketARN,
		TargetType:       catalog.ResourceTypeS3Bucket,
		// Attributes intentionally omits the workgroup OutputLocation URI to
		// keep the relationship payload bucket-only; including the raw URI
		// would leak the result-object prefix and violate the package
		// invariant in README.md / AGENTS.md.
		SourceRecordID: sourceID + "->" + catalog.RelationshipAthenaWorkGroupUsesResultBucket + ":" + bucketARN,
	}
}
