// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package workspaces

import (
	"strings"
)

// workspaceInDirectoryRelationship records a WorkSpace's membership in its
// parent WorkSpaces directory. The target is keyed by the directory node's
// published resource_id (the synthesized WorkSpaces directory ARN) so the edge
// joins the directory node this scanner publishes, not the Directory Service
// node. It returns nil when either endpoint identity is missing.

// workspaceUsesBundleRelationship records a WorkSpace's dependency on the bundle
// it was created from. The target is the WorkSpaces bundle node keyed by its
// published resource_id (the synthesized WorkSpaces bundle ARN). It returns nil
// when either endpoint identity is missing.

// workspaceUsesKMSKeyRelationship records a WorkSpace's reported volume
// encryption KMS key dependency. WorkSpaces reports a key ARN, which matches how
// the KMS scanner publishes its key resource_id (bare id or key ARN). It
// returns nil when no key is reported.

// directoryRelationships records every cross-service edge a WorkSpaces directory
// reports: the underlying Directory Service directory, the placement subnets,
// the assigned security group, the WorkSpaces IAM role, and the associated IP
// access control groups. It returns nil when the directory has no usable
// identity.

// directoryUsesDSDirectoryRelationship records the WorkSpaces directory's link
// to the underlying AWS Directory Service directory. The target is the BARE
// directory id (for example "d-1234567890") the ds scanner publishes as its
// resource_id, so the edge joins the DS node, not a synthesized ARN.

// directorySubnetRelationships records a WorkSpaces directory's placement in
// each reported VPC subnet. The target is the bare subnet id the ec2 scanner
// publishes.

// directoryUsesSecurityGroupRelationship records the WorkSpaces security group
// assigned to new WorkSpaces in the directory. The target is the bare security
// group id the ec2 scanner publishes.

// directoryUsesIAMRoleRelationship records the IAM role WorkSpaces assumes to
// call other services on the account's behalf. WorkSpaces reports the role ARN,
// which matches how the iam scanner publishes its role resource_id. It returns
// nil when no role is reported.

// directoryIPGroupRelationships records a WorkSpaces directory's association
// with each IP access control group. The target is the WorkSpaces IP-group node
// keyed by its published resource_id (the synthesized WorkSpaces IP-group ARN).

// arnOrEmpty returns value when it is ARN-shaped, otherwise "". It keeps a bare
// id from being copied into a target_arn/source_arn field where an ARN is
// expected.
func arnOrEmpty(value string) string {
	if isARN(value) {
		return strings.TrimSpace(value)
	}
	return ""
}
