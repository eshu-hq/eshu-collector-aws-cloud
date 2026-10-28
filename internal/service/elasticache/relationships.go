// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package elasticache

import (
	"strings"
)

// relationshipRecordID encodes the relationship type into the durable
// SourceRecordID alongside the source and final target identity, matching the
// shape used by the RDS scanner. Including the relationship type keeps each
// relationship envelope's source ref distinct when a source has multiple edges
// to the same target and stays stable when the final target identity is
// upgraded from a raw cluster/user ID to the cluster/user ARN.
func relationshipRecordID(sourceID, relationshipType, targetID string) string {
	return strings.TrimSpace(sourceID) + "->" + strings.TrimSpace(relationshipType) + ":" + strings.TrimSpace(targetID)
}
