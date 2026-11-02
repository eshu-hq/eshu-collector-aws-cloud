// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

// cloudWatchLogsLogGroupRecord gives a DescribeLogGroups row its typed home
// and the KMS edge the in-tree logGroupEnvelopes emits. The translation
// mirrors the in-tree logGroupObservation fields the describe read returns
// inline, with one exception (see below); tags stay nil because the listing
// makes no ListTagsForResource call.
func cloudWatchLogsLogGroupRecord(group cloudwatchlogstypes.LogGroup, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(group.Arn))
	name := strings.TrimSpace(aws.ToString(group.LogGroupName))
	row := record(arn, catalog.ServiceCloudWatchLogs, region, name, "log-group")
	resourceID := netdataFirstNonEmpty(arn, name)
	kmsKeyID := strings.TrimSpace(aws.ToString(group.KmsKeyId))
	resource := &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceCloudWatchLogs,
		ResourceType: cloudWatchLogsLogGroupResourceType,
		ResourceID:   resourceID,
		Name:         name,
		ARN:          arn,
		Attributes: map[string]any{
			"creation_time":       netdataTimeMillis(group.CreationTime),
			"retention_in_days":   aws.ToInt32(group.RetentionInDays),
			"stored_bytes":        aws.ToInt64(group.StoredBytes),
			"metric_filter_count": aws.ToInt32(group.MetricFilterCount),
			"log_group_class":     strings.TrimSpace(string(group.LogGroupClass)),
			"kms_key_id":          kmsKeyID,
			"deletion_protected":  aws.ToBool(group.DeletionProtectionEnabled),
			// No bearer_token_authentication_enabled: the in-tree
			// logGroupObservation carries that bool, but the SDK
			// share-safe guard rejects the token substring and the host
			// intake would reject the fact too, failing every claim
			// (eshu-hq/eshu#8852 production proof). One-field exception
			// to the mirrors-in-tree-fields rule; restore via the SDK
			// allowlist follow-up, not by re-adding the key here.
		},
		CorrelationAnchors: []string{arn, name},
		SourceRecordID:     resourceID,
	}
	row.Resource = resource
	row.TypedOnly = true
	if resourceID == "" || kmsKeyID == "" {
		return row
	}
	targetARN := ""
	if strings.HasPrefix(kmsKeyID, "arn:") {
		targetARN = kmsKeyID
	}
	row.Relationships = append(row.Relationships, collector.LiveRelationship{
		Region: region, ServiceKind: catalog.ServiceCloudWatchLogs,
		RelationshipType: cloudWatchLogsLogGroupUsesKMSKeyRelationship,
		SourceResourceID: resourceID, SourceARN: arn,
		TargetResourceID: kmsKeyID, TargetARN: targetARN,
		TargetType:     "aws_kms_key",
		SourceRecordID: resourceID + "->" + cloudWatchLogsLogGroupUsesKMSKeyRelationship + ":" + kmsKeyID,
	})
	return row
}
