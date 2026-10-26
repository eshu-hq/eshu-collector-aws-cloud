// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package checkpoint

import (
	"testing"
	"time"

	awscloud "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// frozenBoundary is the fixed claim identity every vector below reuses.
func frozenBoundary() awscloud.Boundary {
	return awscloud.Boundary{
		AccountID:           "123456789012",
		Region:              "us-east-1",
		ServiceKind:         "s3",
		ScopeID:             "scope-1",
		GenerationID:        "gen-9",
		CollectorInstanceID: "instance-7",
		FencingToken:        42,
		ObservedAt:          time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
	}
}

// TestScopeFromBoundaryParity freezes the claim-identity projection: every
// Scope field copies the matching Boundary field so adapters cannot omit
// generation fencing.
func TestScopeFromBoundaryParity(t *testing.T) {
	t.Parallel()
	got := ScopeFromBoundary(frozenBoundary())
	want := Scope{
		CollectorInstanceID: "instance-7",
		AccountID:           "123456789012",
		Region:              "us-east-1",
		ServiceKind:         "s3",
		GenerationID:        "gen-9",
		FencingToken:        42,
	}
	if got != want {
		t.Fatalf("ScopeFromBoundary() = %#v, want %#v", got, want)
	}
}

// TestKeyIdentityParity freezes the storage key encoding: NUL-joined fields
// in a fixed order. ResourceParent may carry an ARN, so the encoding must
// never be used as a metric label.
func TestKeyIdentityParity(t *testing.T) {
	t.Parallel()
	key := Key{Scope: ScopeFromBoundary(frozenBoundary()), Operation: "ListBuckets"}
	want := "instance-7\x00123456789012\x00us-east-1\x00s3\x00gen-9\x00\x00ListBuckets"
	if got := key.Identity(); got != want {
		t.Fatalf("Identity() = %q, want %q", got, want)
	}
	arnKey := Key{
		Scope:          ScopeFromBoundary(frozenBoundary()),
		ResourceParent: "arn:aws:s3:::example",
		Operation:      "ListObjects",
	}
	wantARN := "instance-7\x00123456789012\x00us-east-1\x00s3\x00gen-9\x00arn:aws:s3:::example\x00ListObjects"
	if got := arnKey.Identity(); got != wantARN {
		t.Fatalf("Identity() = %q, want %q", got, wantARN)
	}
}

// TestKeyValidateParity freezes the storage-gate rejections.
func TestKeyValidateParity(t *testing.T) {
	t.Parallel()
	valid := Key{Scope: ScopeFromBoundary(frozenBoundary()), Operation: "ListBuckets"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	noOp := Key{Scope: ScopeFromBoundary(frozenBoundary())}
	if err := noOp.Validate(); err == nil || err.Error() != "aws pagination checkpoint operation is required" {
		t.Fatalf("Validate() error = %v, want the operation-required error", err)
	}
	noFence := Key{
		Scope:     Scope{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "s3", GenerationID: "gen-9"},
		Operation: "ListBuckets",
	}
	if err := noFence.Validate(); err == nil {
		t.Fatal("Validate() = nil, want an error for the missing collector_instance_id")
	}
	zeroFence := Key{Scope: ScopeFromBoundary(frozenBoundary()), Operation: "ListBuckets"}
	zeroFence.Scope.FencingToken = 0
	if err := zeroFence.Validate(); err == nil || err.Error() != "aws pagination checkpoint fencing_token must be positive" {
		t.Fatalf("Validate() error = %v, want the fencing-token error", err)
	}
}

// TestCheckpointValidateParity freezes the persisted-checkpoint gate.
func TestCheckpointValidateParity(t *testing.T) {
	t.Parallel()
	valid := Checkpoint{Key: Key{Scope: ScopeFromBoundary(frozenBoundary()), Operation: "List"}, PageNumber: 3}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	negative := Checkpoint{Key: Key{Scope: ScopeFromBoundary(frozenBoundary()), Operation: "List"}, PageNumber: -1}
	if err := negative.Validate(); err == nil || err.Error() != "aws pagination checkpoint page_number must be non-negative" {
		t.Fatalf("Validate() error = %v, want the page-number error", err)
	}
}
