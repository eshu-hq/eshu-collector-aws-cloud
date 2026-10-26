// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package iam

import (
	"testing"
)

// This file pins the ported behavior of package iam against the in-tree
// counterpart. Every vector below is frozen: the const pins repeat the exact
// in-tree literals, and the helper tables encode the verified canonical
// semantics (see the generator notes in the port report).

func TestPortParity_Const_PolicySourceInline(t *testing.T) {
	t.Parallel()
	if got, want := PolicySourceInline, "inline"; got != want {
		t.Fatalf("PolicySourceInline = %#v, want %#v", got, want)
	}
}

func TestPortParity_Const_PolicySourceAttachedManaged(t *testing.T) {
	t.Parallel()
	if got, want := PolicySourceAttachedManaged, "attached_managed"; got != want {
		t.Fatalf("PolicySourceAttachedManaged = %#v, want %#v", got, want)
	}
}

func TestPortParity_Const_PolicySourceTrust(t *testing.T) {
	t.Parallel()
	if got, want := PolicySourceTrust, "trust"; got != want {
		t.Fatalf("PolicySourceTrust = %#v, want %#v", got, want)
	}
}

func TestPortParity_Const_PolicySourcePermissionBoundary(t *testing.T) {
	t.Parallel()
	if got, want := PolicySourcePermissionBoundary, "permission_boundary"; got != want {
		t.Fatalf("PolicySourcePermissionBoundary = %#v, want %#v", got, want)
	}
}
