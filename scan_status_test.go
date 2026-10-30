// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"strings"
	"testing"
)

func TestSanitizeScanStatusMessageRedactsAndBounds(t *testing.T) {
	t.Parallel()

	message := strings.Repeat("prefix ", 60) +
		"arn:aws:sts::123456789012:assumed-role/Admin/session " +
		"request 7bb9d111-4c2c-4f8b-9b7a-72f1aa2a0c55\nAKIAABCDEFGHIJKLMNOP"
	got := SanitizeScanStatusMessage(message)

	for _, forbidden := range []string{
		"123456789012",
		"arn:aws",
		"7bb9d111-4c2c-4f8b-9b7a-72f1aa2a0c55",
		"AKIAABCDEFGHIJKLMNOP",
		"\n",
	} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("SanitizeScanStatusMessage() = %q, contains %q", got, forbidden)
		}
	}
	if len(got) > MaxScanStatusMessageLength {
		t.Fatalf("SanitizeScanStatusMessage() length = %d, want <= %d", len(got), MaxScanStatusMessageLength)
	}
}

// TestWarningTaxonomyMatchesInTree pins the Wave 0 warning-kind taxonomy
// against the in-tree values: a scanner-side string drift would fork warning
// identity between the two pipelines and break the Q4(d) warning-class
// mapping at deletion time.
func TestWarningTaxonomyMatchesInTree(t *testing.T) {
	t.Parallel()

	for name, pair := range map[string][2]string{
		"budget_exhausted":   {WarningBudgetExhausted, "budget_exhausted"},
		"throttle_sustained": {WarningThrottleSustained, "throttle_sustained"},
		"network_timeout":    {WarningNetworkTimeout, "network_timeout"},
		"assumerole_failed":  {WarningAssumeRoleFailed, "assumerole_failed"},
		"org_access_skipped": {WarningOrganizationsOrgAccessSkipped, "organizations_org_access_skipped"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want in-tree %q", name, pair[0], pair[1])
		}
	}
}
