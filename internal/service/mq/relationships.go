// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package mq

import (
	"strings"
)

// brokerRelationships builds the relationship observations for one broker.
// configurationARNs maps a broker-reported configuration ID to the ARN of the
// emitted aws_mq_configuration resource so the broker→configuration edge joins
// on the same identity the configuration scanner publishes as its ResourceID.

// The aws_mq_configuration resource is emitted with ResourceID set
// to its ARN, so the edge must target the ARN to join. When the
// referenced configuration is absent from ListConfigurations (for
// example a shared or cross-account configuration), fall back to the
// broker-reported ID, which the configuration resource carries as a
// correlation anchor, rather than dropping the edge.

// The cloudwatchlogs scanner emits each log group with ResourceID set to
// its non-wildcard ARN, so synthesize the matching ARN from the broker
// partition and the boundary account and region and target it in both
// fields, otherwise the edge cannot join the log group resource.

// cloudWatchLogGroupARN synthesizes the non-wildcard CloudWatch Logs log group
// ARN the cloudwatchlogs scanner publishes as its resource ResourceID, so a
// broker logging edge joins on the same identity. Amazon MQ reports broker log
// destinations as bare log group names; the ARN form is
// arn:<partition>:logs:<region>:<account>:log-group:<name>. The partition is
// taken from the broker ARN so the edge joins in the aws-us-gov and aws-cn
// partitions, not only the commercial aws partition.

// brokerLogGroups returns the distinct CloudWatch Logs log group targets a
// broker reports. General and audit destinations are returned separately so a
// single broker can link to both groups, and an empty group name is skipped.

// relationshipRecordID encodes the relationship type into the durable
// SourceRecordID alongside the source and target identity. Including the
// relationship type keeps each relationship envelope's source ref distinct when
// a broker has multiple edges to the same target.
func relationshipRecordID(sourceID, relationshipType, targetID string) string {
	return strings.TrimSpace(sourceID) + "->" + strings.TrimSpace(relationshipType) + ":" + strings.TrimSpace(targetID)
}
