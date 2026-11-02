// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func TestAppendLiveDNSRecordsBindsClaimAndDeduplicates(t *testing.T) {
	claim := testClaim()
	base := mustCollect(t, "complete.json", claim, testObservedAt(), "")
	observation := DNSRecordObservation{
		Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "route53"},
		HostedZoneID: "/hostedzone/Z123",
		RecordName:   "example.com.",
		RecordType:   "A",
	}
	result, err := AppendLiveDNSRecords(base, []DNSRecordObservation{observation, observation}, "aws://123456789012", ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Facts) != len(base.Facts)+1 {
		t.Fatalf("facts = %d, want %d", len(result.Facts), len(base.Facts)+1)
	}
	fact := result.Facts[len(result.Facts)-1]
	if fact.Kind != AWSKindDNSRecord || fact.SourceRef.ScopeID != claim.Scope.ID || fact.SourceRef.GenerationID != claim.GenerationID {
		t.Fatalf("DNS record is not bound to claim: %#v", fact.SourceRef)
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected claim-bound DNS result: %v", err)
	}
}
