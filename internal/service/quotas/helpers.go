// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package servicequotas

import "strings"

// quotaResourceID returns the resource_id the service-quota node publishes. It
// prefers the quota ARN (always present from the Service Quotas API) and falls
// back to a stable "<service_code>/<quota_code>" key so a quota with a missing
// ARN still keys deterministically within its account/region scope.

// floatOrNil returns the float when set, or nil so an unknown quota value is
// omitted from the attribute payload instead of emitting a misleading zero.

// int32OrNil returns the int32 when set, or nil so an unknown rate-period
// magnitude is omitted instead of emitting a misleading zero.

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
