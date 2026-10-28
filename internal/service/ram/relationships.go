// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package ram

import (
	"time"
)

// shareJoinID resolves the join key used for a resource share across its
// resource fact and every relationship that sources from it. RAM normally
// reports a resource share ARN, but a defensively blank ARN falls back to the
// share name so a malformed record does not fail the whole scan and so the
// share's resource fact and edges still join on the same key. It returns the
// empty string only when both the ARN and the name are blank.

// shareResourceRelationship records that a resource share shares one resource.
// The target is the shared resource's ARN, and the target type is the
// RAM-reported resource type (service-code:resource-code, for example
// ec2:subnet). When RAM reports a blank type, the edge falls back to the
// generic resource target type so it keeps a non-empty target type and does not
// violate the relationship invariant; the RAM-reported type is preserved in the
// attributes either way. The source join key is the share ARN, or the share
// name when the ARN is blank. It returns false for an empty share join key or
// resource ARN so a blank record does not emit a dangling edge.

// sharePrincipalRelationship records that a resource share targets one
// principal. The principal id is an AWS account id, an Organizations OU ARN, or
// an Organizations organization or root ARN. The relationship type and target
// type are derived from the principal id form so each edge joins to the
// organizations scanner's resource id convention:
//
//   - a 12-digit account id targets aws_organizations_account by bare account
//     id (the organizations scanner emits the bare account id as its account
//     resource id);
//   - an OU ARN (path segment :ou/) targets
//     aws_organizations_organizational_unit by ARN;
//   - an organization or root ARN (path segment :organization/ or :root/)
//     targets aws_organizations_root by ARN.
//
// An unrecognized principal form targets the generic resource type with a
// distinct relationship type rather than masquerading as an account. The source
// join key is the share ARN, or the share name when the ARN is blank. It
// returns false for an empty share join key or principal id.

// sharePermissionRelationship records that a resource share uses one managed
// permission. The target is the permission ARN. The source join key is the
// share ARN, or the share name when the ARN is blank. It returns false for an
// empty share join key or permission ARN.

// classifyPrincipal maps a RAM principal id to its relationship type, target
// type, and (for ARN principals) target ARN. A bare account id produces no
// target ARN because the organizations scanner keys accounts by bare id, not
// ARN. ARN classification keys on the resource-path segment rather than the
// partition prefix so non-default partitions (GovCloud, China) classify the
// same way.

// An unrecognized principal id (for example a service principal or a
// future RAM principal form) records a distinct targeted-principal edge
// with the generic target type rather than masquerading as an
// Organizations account. This keeps evidence without inventing a wrong
// account join key; the raw principal id remains the join key and no
// derived target ARN is claimed.

// isAccountID reports whether id is a bare 12-digit AWS account id.

func timeOrNil(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}
