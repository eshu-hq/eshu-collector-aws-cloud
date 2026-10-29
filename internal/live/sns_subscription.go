// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// snsSubscriptionRecord retains subscription metadata and an edge only when
// the API reports an ARN endpoint. Other endpoints never enter fact payloads.
func snsSubscriptionRecord(topicARN, region string, subscription snstypes.Subscription) collector.Record {
	subscriptionARN := strings.TrimSpace(aws.ToString(subscription.SubscriptionArn))
	protocol := strings.TrimSpace(aws.ToString(subscription.Protocol))
	row := record(subscriptionARN, "sns", region, protocol, "subscription")
	sourceARN := strings.TrimSpace(topicARN)
	endpointARN := strings.TrimSpace(aws.ToString(subscription.Endpoint))
	if sourceARN == "" || !strings.HasPrefix(endpointARN, "arn:") {
		return row
	}
	targetType := "aws_resource"
	switch {
	case strings.Contains(endpointARN, ":sqs:"):
		targetType = "aws_sqs_queue"
	case strings.Contains(endpointARN, ":lambda:"):
		targetType = "aws_lambda_function"
	}
	recordID := subscriptionARN
	if recordID == "" {
		recordID = sourceARN + "->" + endpointARN
	}
	row.Relationships = []collector.LiveRelationship{{
		Region: region, ServiceKind: "sns", RelationshipType: "sns_topic_delivers_to_resource",
		SourceResourceID: sourceARN, SourceARN: sourceARN,
		TargetResourceID: endpointARN, TargetARN: endpointARN, TargetType: targetType,
		SourceRecordID: recordID,
		Attributes: map[string]any{
			"owner":            strings.TrimSpace(aws.ToString(subscription.Owner)),
			"protocol":         protocol,
			"subscription_arn": subscriptionARN,
		},
	}}
	return row
}
