// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package networkmanager

import (
	"strings"
	"time"
)

// globalNetworkResourceID returns the resource_id the global-network node
// publishes. It prefers the API-reported ARN (Network Manager always returns
// one) and synthesizes the partition-aware ARN from the boundary account when a
// fixture omits it, so child parent edges key the same value the node publishes.

// globalNetworkARN synthesizes the partition-aware ARN for a global-network id,
// matching the region-less Network Manager ARN shape AWS publishes
// (arn:<partition>:networkmanager::<account>:global-network/<id>). It returns ""
// when the id is empty.

// siteARN synthesizes the partition-aware ARN for a site id within a global
// network, matching the Network Manager ARN shape
// (arn:<partition>:networkmanager::<account>:site/<global-network-id>/<site-id>).
// It returns "" when either id is empty.

// deviceARN synthesizes the partition-aware ARN for a device id within a global
// network, matching the Network Manager ARN shape. It returns "" when either id
// is empty.

// linkARN synthesizes the partition-aware ARN for a link id within a global
// network, matching the Network Manager ARN shape. It returns "" when either id
// is empty.

// networkManagerARN builds a region-less Network Manager ARN for resourcePath
// using the boundary partition and account. Network Manager is global, so the
// ARN region segment is empty; the partition is derived from the boundary so
// GovCloud and China edges resolve instead of dangling. It returns "" when the
// account id is missing, since a parent edge keyed to an account-less ARN would
// never join the real node.

// transitGatewayID extracts the bare transit gateway id (tgw-...) from a transit
// gateway ARN. The transit gateway scanner publishes its resource_id as the bare
// id, not an ARN, so registration edges must key the id rather than the ARN.
// Network Manager reports the ARN
// (arn:<partition>:ec2:<region>:<account>:transit-gateway/tgw-...), so the id is
// the final path segment. It returns "" when no id can be extracted.

// isARN reports whether value carries the canonical AWS ARN prefix.
func isARN(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "arn:")
}

// timeOrNil returns the UTC time when value is set, or nil for the zero time so
// the attribute payload omits an unknown timestamp instead of emitting an epoch.
func timeOrNil(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

// cloneStringMap returns a trimmed-key copy of input, or nil when it is empty or
// every key trims to empty, keeping omitempty-style payload behavior consistent.
func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		output[trimmed] = value
	}
	if len(output) == 0 {
		return nil
	}
	return output
}

// cloneStrings returns a trimmed copy of input with empty entries dropped, or
// nil when nothing survives.
func cloneStrings(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	output := make([]string, 0, len(input))
	for _, value := range input {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			output = append(output, trimmed)
		}
	}
	if len(output) == 0 {
		return nil
	}
	return output
}
