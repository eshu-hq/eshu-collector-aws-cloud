// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package keyspaces

import (
	"strings"
)

// tableKeyspaceRelationship emits the table-in-keyspace edge. The keyspace node
// publishes its ARN as resource_id, so the edge targets the keyspace ARN. The
// keyspace ARN is taken from the table model when the adapter resolved it and is
// otherwise derived from the table's own ARN by stripping the trailing
// "/table/<name>" segment. Deriving from the table ARN inherits the table ARN's
// partition (aws / aws-cn / aws-us-gov), so the edge never dangles in GovCloud or
// China the way a hardcoded commercial partition would.

// tableKMSRelationship emits the table-uses-KMS-key edge when the table reports a
// customer-managed KMS key. AWS-owned keys report no key identifier, so no edge
// is emitted for them. The KMS key scanner publishes its key node keyed by ARN,
// so the target is keyed by the reported KMS key ARN. target_arn is set only when
// the identifier is ARN-shaped, mirroring the DynamoDB scanner.

// keyspaceARNFromTableARN derives the parent keyspace ARN from an Amazon
// Keyspaces table ARN by stripping the trailing "/table/<name>" segment. Table
// ARNs have the form
// "arn:<partition>:cassandra:<region>:<account>:/keyspace/<ks>/table/<name>" and
// keyspace ARNs have the form
// "arn:<partition>:cassandra:<region>:<account>:/keyspace/<ks>/", so the derived
// ARN inherits the table ARN's partition. It returns "" when the input is not a
// recognizable Keyspaces table ARN.

// Re-anchor tableStart to the full string and keep the trailing slash so the
// derived ARN matches the keyspace node's published ARN exactly.

func isARN(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "arn:")
}
