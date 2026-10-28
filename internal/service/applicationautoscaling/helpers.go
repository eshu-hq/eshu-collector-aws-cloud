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

// targetResourceARN synthesizes the partition-aware ARN of the resource a
// scalable target governs, matching the resource_id the target service's
// scanner publishes, so the scale edge joins the real resource node instead of
// dangling. It returns "" with a false targetType for any namespace the repo
// does not scan to a stable ARN-keyed node (spot fleet, appstream, sagemaker,
// comprehend, cassandra, kafka, elasticache, neptune, workspaces, custom
// resource, DynamoDB global secondary index), so the caller skips the edge.
//
// partition is derived from the scan boundary by the caller; the function never
// hardcodes arn:aws:.

// Only a base table target maps to a DynamoDB table node. A global
// secondary index target (table/<t>/index/<i>) has no dedicated node, so
// it is skipped rather than mis-keyed to the table ARN.

// service/<cluster>/<service> -> the long-format ECS service ARN.

// cluster:<name> -> the Aurora DB cluster ARN.

// function:<name>[:<qualifier>] -> the base function ARN the Lambda node
// publishes (the version/alias qualifier is dropped).

// policyResourceID returns the resource_id the scaling-policy node publishes.
// It prefers the policy ARN and falls back to a composite of the owning
// namespace, dimension, resource id, and policy name so the node and its edges
// share a stable id even when AWS omits the ARN.

// scheduledActionResourceID returns the resource_id the scheduled-action node
// publishes. It prefers the action ARN and falls back to a composite of the
// owning namespace, dimension, resource id, and action name.

// lambdaFunctionName extracts the base function name from a Lambda scalable
// target resource id of the form function:<name>[:<qualifier>]. It returns the
// bare name without the version or alias qualifier so the synthesized ARN
// matches the function node's resource_id, and false when the shape is unknown.

// arnPrefix builds the leading arn:<partition>:<service>:<region>:<account>
// segment of an AWS ARN. The partition is supplied by the caller from the scan
// boundary, never hardcoded, so synthesized identities match the resource node
// in every partition.

// timeOrNil returns the UTC time when value is set, or nil for the zero time so
// the attribute payload omits an unknown timestamp instead of emitting an epoch.

// int32OrNil returns the dereferenced value, or nil when the pointer is unset,
// so the attribute payload omits an unknown bound instead of emitting zero.

// boolOrNil returns the dereferenced value, or nil when the pointer is unset.

// cloneStrings returns a trimmed copy of input with empty entries dropped, or
// nil when nothing survives.
