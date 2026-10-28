// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package applicationautoscaling

import (
	"strings"
)

// scalableTargetResourceID returns the resource_id the scalable-target node
// publishes. Application Auto Scaling has no single ARN per target across all
// namespaces, so the scanner keys a scalable target by the composite of its
// service namespace, scalable dimension, and scaled resource id. That triple is
// exactly what uniquely identifies a registered target, so policy and scheduled
// action edges can key the same value. The scalable dimension is part of that
// identity: one resource can register multiple targets (for example a DynamoDB
// table with both read- and write-capacity targets), so dropping the dimension
// would collapse distinct targets onto one id. It returns "" when any of the
// three identifying parts is missing.
func scalableTargetResourceID(serviceNamespace, scalableDimension, resourceID string) string {
	namespace := strings.TrimSpace(serviceNamespace)
	dimension := strings.TrimSpace(scalableDimension)
	resource := strings.TrimSpace(resourceID)
	if namespace == "" || dimension == "" || resource == "" {
		return ""
	}
	return namespace + "/" + dimension + "/" + resource
}
