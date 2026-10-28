// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package servicediscovery

import (
	"strings"
	"time"
)

// serviceResourceID is the join key the Cloud Map service resource is keyed by:
// "namespaceName/serviceName". The App Mesh virtual-node service-discovery edge
// targets this exact identity with target_type aws_cloud_map_service, so the
// edge resolves only when the service resource uses the same id. It returns ""
// when either half is blank so a malformed service never emits a key that
// cannot join.

// namespaceObservation maps one Cloud Map namespace into an aws_resource
// observation keyed by the Cloud Map namespace id.

// serviceObservation maps one Cloud Map service into an aws_resource
// observation keyed by "namespaceName/serviceName". It records the instance
// count only; instance attribute maps are never read or persisted.

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

func timeOrNil(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}
