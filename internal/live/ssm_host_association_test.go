// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"
)

// TestCanonicalSSMInventoryParameters pins the accepted-record association
// form: applications Enabled, files and windowsRegistry omitted (document
// default, collects neither), every other toggle explicitly Disabled, and no
// resource-data-sync destination.
func TestCanonicalSSMInventoryParameters(t *testing.T) {
	t.Parallel()
	params := CanonicalSSMInventoryParameters()
	if params["applications"] != "Enabled" {
		t.Fatalf("applications = %q, want Enabled", params["applications"])
	}
	for key, value := range params {
		switch key {
		case "applications":
			continue
		case "files", "windowsRegistry":
			t.Fatalf("canonical form carries %q, which the agent rejects as Disabled", key)
		default:
			if value != "Disabled" {
				t.Fatalf("canonical toggle %q = %q, want Disabled", key, value)
			}
		}
	}
	toggles := []string{
		"awsComponents", "networkConfig", "windowsUpdates",
		"instanceDetailedInformation", "services", "windowsRoles", "customInventory", "billingInfo",
	}
	for _, toggle := range toggles {
		if params[toggle] != "Disabled" {
			t.Fatalf("canonical form leaves %q at %q, want explicit Disabled", toggle, params[toggle])
		}
	}
	if err := ValidateSSMInventoryParameters(params); err != nil {
		t.Fatalf("canonical form rejected: %v", err)
	}
}

func TestValidateSSMInventoryParameters(t *testing.T) {
	t.Parallel()
	canonical := CanonicalSSMInventoryParameters()
	with := func(key, value string) map[string]string {
		out := map[string]string{}
		for k, v := range canonical {
			out[k] = v
		}
		if value == "" {
			delete(out, key)
		} else {
			out[key] = value
		}
		return out
	}
	cases := []struct {
		name   string
		params map[string]string
	}{
		{"files present", with("files", "Disabled")},
		{"windowsRegistry present", with("windowsRegistry", "Disabled")},
		{"applications disabled", with("applications", "Disabled")},
		{"applications missing", with("applications", "")},
		{"toggle enabled", with("networkConfig", "Enabled")},
		{"toggle missing", with("services", "")},
		{"unknown parameter", with("s3SyncBucket", "Disabled")},
		{"sync destination", with("destinationBucket", "Disabled")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateSSMInventoryParameters(tc.params); err == nil {
				t.Fatalf("non-canonical parameters accepted: %v", tc.params)
			}
		})
	}
	if err := ValidateSSMInventoryParameters(nil); err == nil {
		t.Fatal("nil parameters accepted")
	}
}
