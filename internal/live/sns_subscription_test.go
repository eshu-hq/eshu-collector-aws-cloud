// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
)

func TestSNSSubscriptionRelationshipExcludesPrivateEndpoints(t *testing.T) {
	topicARN := "arn:aws:sns:us-east-1:123456789012:orders"
	queueARN := "arn:aws:sqs:us-east-1:123456789012:orders"
	row := snsSubscriptionRecord(topicARN, "us-east-1", snstypes.Subscription{
		SubscriptionArn: aws.String("arn:aws:sns:us-east-1:123456789012:orders:sub-1"),
		Endpoint:        aws.String("  " + queueARN + "  "), Protocol: aws.String("sqs"), Owner: aws.String("123456789012"),
	})
	if len(row.Relationships) != 1 || row.Relationships[0].RelationshipType != "sns_topic_delivers_to_resource" || row.Relationships[0].TargetResourceID != queueARN || row.Relationships[0].TargetType != "aws_sqs_queue" {
		t.Fatalf("SNS queue relationship = %#v", row.Relationships)
	}
	for _, endpoint := range []string{"private@example.com", "+15551234567", "https://example.com/private"} {
		private := snsSubscriptionRecord(topicARN, "us-east-1", snstypes.Subscription{Endpoint: aws.String(endpoint), Protocol: aws.String("https")})
		if len(private.Relationships) != 0 {
			t.Fatalf("private endpoint %q produced relationship: %#v", endpoint, private.Relationships)
		}
	}
}
