// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awssnstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/smithy-go"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

// snsTopicRecord gives a ListTopics entry its typed home. Display name and
// delivery-policy attributes come from one GetTopicAttributes read per
// topic; tags stay nil because the listing makes no ListTagsForResource
// call. A denied attributes read keeps the bare row behind an optional
// denial (see listSNS), so one missing permission never drops the topic.
func snsTopicRecord(topicARN string, attrs map[string]string, region string) collector.Record {
	arn := strings.TrimSpace(topicARN)
	name := lastSegment(arn, ":")
	if display := strings.TrimSpace(attrs["DisplayName"]); display != "" {
		name = display
	}
	row := record(arn, catalog.ServiceSNS, region, name, "topic")
	row.Resource = &collector.LiveResource{
		Region:       region,
		ServiceKind:  catalog.ServiceSNS,
		ResourceType: catalog.ResourceTypeSNSTopic,
		ResourceID:   netdataFirstNonEmpty(arn, name),
		Name:         name,
		ARN:          arn,
		Attributes: map[string]any{
			"archive_policy":              strings.TrimSpace(attrs["ArchivePolicy"]),
			"beginning_archive_time":      strings.TrimSpace(attrs["BeginningArchiveTime"]),
			"content_based_deduplication": snsParseBool(attrs["ContentBasedDeduplication"]),
			"display_name":                strings.TrimSpace(attrs["DisplayName"]),
			"fifo_topic":                  snsParseBool(attrs["FifoTopic"]),
			"kms_master_key_id":           strings.TrimSpace(attrs["KmsMasterKeyId"]),
			"owner":                       strings.TrimSpace(attrs["Owner"]),
			"signature_version":           strings.TrimSpace(attrs["SignatureVersion"]),
			"subscriptions_confirmed":     strings.TrimSpace(attrs["SubscriptionsConfirmed"]),
			"subscriptions_deleted":       strings.TrimSpace(attrs["SubscriptionsDeleted"]),
			"subscriptions_pending":       strings.TrimSpace(attrs["SubscriptionsPending"]),
			"tracing_config":              strings.TrimSpace(attrs["TracingConfig"]),
		},
		CorrelationAnchors: []string{arn, name},
		SourceRecordID:     netdataFirstNonEmpty(arn, name),
	}
	row.TypedOnly = true
	return row
}

// snsSubscriptionRelationship gives a ListSubscriptionsByTopic entry its
// typed home: a delivers-to edge from the topic to the endpoint, mirroring
// the in-tree subscriptionRelationship. Only ARN-addressable endpoints
// (queues, functions) produce an edge; email and SMS endpoints have no
// typed target, matching the in-tree skip.
func snsSubscriptionRelationship(topicARN string, subscription awssnstypes.Subscription, region string) (collector.LiveRelationship, bool) {
	topic := strings.TrimSpace(topicARN)
	endpoint := snsARNOnly(aws.ToString(subscription.Endpoint))
	if topic == "" || endpoint == "" {
		return collector.LiveRelationship{}, false
	}
	return collector.LiveRelationship{
		Region:           region,
		ServiceKind:      catalog.ServiceSNS,
		RelationshipType: catalog.RelationshipSNSTopicDeliversToResource,
		SourceResourceID: netdataFirstNonEmpty(topic, aws.ToString(subscription.TopicArn)),
		SourceARN:        topic,
		TargetResourceID: endpoint,
		TargetARN:        endpoint,
		TargetType:       snsTargetTypeForARN(endpoint),
		SourceRecordID: netdataFirstNonEmpty(
			strings.TrimSpace(aws.ToString(subscription.SubscriptionArn)),
			topic+"->"+endpoint,
		),
	}, true
}

func snsTargetTypeForARN(arn string) string {
	switch {
	case strings.Contains(arn, ":sqs:"):
		return catalog.ResourceTypeSQSQueue
	case strings.Contains(arn, ":lambda:"):
		return catalog.ResourceTypeLambdaFunction
	default:
		return "aws_resource"
	}
}

func snsARNOnly(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if !strings.HasPrefix(endpoint, "arn:") {
		return ""
	}
	return endpoint
}

func snsParseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "t", "true", "y", "yes":
		return true
	default:
		return false
	}
}

// isSNSDenied recognizes the authorization failures that degrade one
// topic-attributes read to a warning. Other API and transport failures
// stay fatal so a misconfigured scan never reads back as partial evidence.
func isSNSDenied(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "AccessDenied", "AccessDeniedException", "AuthorizationError", "UnauthorizedOperation":
		return true
	default:
		return false
	}
}
