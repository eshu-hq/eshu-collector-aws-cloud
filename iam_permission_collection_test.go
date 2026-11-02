// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func iamPermissionTestObservation() IAMPermissionObservation {
	return IAMPermissionObservation{
		Boundary:      Boundary{AccountID: "123456789012", Region: "aws-global", ServiceKind: "iam"},
		PrincipalARN:  "arn:aws:iam::123456789012:role/demo",
		PrincipalType: "aws_iam_role",
		PolicySource:  "inline",
		PolicyName:    "inline-read",
		StatementSID:  "InlineRead",
		Effect:        "Allow",
		Actions:       []string{"s3:GetObject"},
		Resources:     []string{"arn:aws:s3:::assets/*"},
		ConditionKeys: []string{"aws:SourceIp"},
	}
}

// TestAppendLiveIAMPermissionsBindsClaimAndDeduplicates pins the appender
// contract: claim binding plus stable-key dedupe, so a retried observation
// batch cannot double-emit the same statement fact.
func TestAppendLiveIAMPermissionsBindsClaimAndDeduplicates(t *testing.T) {
	claim := testClaim()
	base := mustCollect(t, "complete.json", claim, testObservedAt(), "")
	observation := iamPermissionTestObservation()
	result, err := AppendLiveIAMPermissions(base, []IAMPermissionObservation{observation, observation}, "aws://123456789012", ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Facts) != len(base.Facts)+1 {
		t.Fatalf("facts = %d, want %d", len(result.Facts), len(base.Facts)+1)
	}
	fact := result.Facts[len(result.Facts)-1]
	if fact.Kind != AWSKindIAMPermission || fact.SourceRef.ScopeID != claim.Scope.ID || fact.SourceRef.GenerationID != claim.GenerationID {
		t.Fatalf("permission is not bound to claim: %#v", fact.SourceRef)
	}
	// A retried batch over the same observation must not add a second fact.
	replayed, err := AppendLiveIAMPermissions(result, []IAMPermissionObservation{observation}, "aws://123456789012", ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if len(replayed.Facts) != len(result.Facts) {
		t.Fatalf("retry facts = %d, want idempotent %d", len(replayed.Facts), len(result.Facts))
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(replayed); err != nil {
		t.Fatalf("SDK rejected claim-bound permission result: %v", err)
	}
}

// TestAppendLiveIAMPermissionsRequiresFencingToken keeps the appender
// fail-closed without a claim token.
func TestAppendLiveIAMPermissionsRequiresFencingToken(t *testing.T) {
	claim := testClaim()
	claim.FencingToken = ""
	base := mustCollect(t, "complete.json", claim, testObservedAt(), "")
	if _, err := AppendLiveIAMPermissions(base, []IAMPermissionObservation{iamPermissionTestObservation()}, "aws://123456789012", ResourceUse{}); err == nil {
		t.Fatal("permission append without fencing token succeeded, want fail-closed error")
	}
}
