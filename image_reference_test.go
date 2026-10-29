// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func TestAppendLiveImageReferencesBindsClaimAndDeduplicatesTags(t *testing.T) {
	claim := testClaim()
	base := mustCollect(t, "complete.json", claim, testObservedAt(), "")
	observation := ImageReferenceObservation{
		Boundary:       Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ecr"},
		RepositoryARN:  "arn:aws:ecr:us-east-1:123456789012:repository/team/api",
		RepositoryName: "team/api", RegistryID: "123456789012",
		ImageDigest: "sha256:abc", Tag: "latest", PushedAt: time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
		ImageSizeInBytes: 42,
	}
	result, err := AppendLiveImageReferences(base, []ImageReferenceObservation{observation, observation}, "aws://123456789012", ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Facts) != len(base.Facts)+1 {
		t.Fatalf("facts = %d, want %d", len(result.Facts), len(base.Facts)+1)
	}
	fact := result.Facts[len(result.Facts)-1]
	if fact.Kind != AWSKindImageReference || fact.SourceRef.RecordID != "team/api@sha256:abc#latest" || fact.SourceRef.ScopeID != claim.Scope.ID {
		t.Fatalf("fact identity = %#v", fact)
	}
	if fact.Payload["manifest_digest"] != "sha256:abc" || fact.Payload["tag"] != "latest" || fact.Payload["image_size_in_bytes"] != int64(42) {
		t.Fatalf("payload = %#v", fact.Payload)
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected image reference: %v", err)
	}
}
