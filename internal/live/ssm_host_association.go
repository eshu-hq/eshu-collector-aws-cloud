// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"fmt"
	"sort"
	"strings"
)

// Canonical inventory toggles for the AWS-GatherSoftwareInventory document,
// verified 2026-10-29 via DescribeDocument: every parameter the document
// declares except applications (the collected type) and files plus
// windowsRegistry (omitted: those parameters take JSON path specs, not
// Enabled/Disabled toggles, which is why the agent rejects explicit
// "Disabled"). Most toggles default to Enabled, so the canonical form
// names each one explicitly: a missing toggle would collect by default.
var canonicalSSMInventoryToggles = []string{
	"awsComponents",
	"networkConfig",
	"windowsUpdates",
	"instanceDetailedInformation",
	"services",
	"windowsRoles",
	"customInventory",
	"billingInfo",
}

// CanonicalSSMInventoryParameters returns the accepted-record association
// form: applications Enabled, files and windowsRegistry omitted (document
// default, collects neither), every other toggle explicitly Disabled, and
// no resource-data-sync destination (sync is a separate association, never
// a parameter of this document).
func CanonicalSSMInventoryParameters() map[string]string {
	params := map[string]string{"applications": "Enabled"}
	for _, toggle := range canonicalSSMInventoryToggles {
		params[toggle] = "Disabled"
	}
	return params
}

// ValidateSSMInventoryParameters fails closed unless the parameter map is
// exactly the canonical form: applications Enabled, files and
// windowsRegistry absent, every documented toggle explicitly Disabled,
// and no other key (an unknown parameter would collect under its document
// default, and any sync destination widens the scope beyond API reads).
func ValidateSSMInventoryParameters(params map[string]string) error {
	if len(params) == 0 {
		return fmt.Errorf("ssm inventory association requires explicit parameters")
	}
	if strings.TrimSpace(params["applications"]) != "Enabled" {
		return fmt.Errorf("ssm inventory association must collect applications explicitly")
	}
	for _, omitted := range []string{"files", "windowsRegistry"} {
		if _, present := params[omitted]; present {
			return fmt.Errorf("ssm inventory association must omit %q (document default collects neither)", omitted)
		}
	}
	for _, toggle := range canonicalSSMInventoryToggles {
		value, present := params[toggle]
		if !present {
			return fmt.Errorf("ssm inventory association must disable %q explicitly", toggle)
		}
		if strings.TrimSpace(value) != "Disabled" {
			return fmt.Errorf("ssm inventory association must disable %q explicitly", toggle)
		}
	}
	known := map[string]bool{"applications": true}
	for _, toggle := range canonicalSSMInventoryToggles {
		known[toggle] = true
	}
	extras := []string{}
	for key := range params {
		if !known[key] {
			extras = append(extras, key)
		}
	}
	if len(extras) > 0 {
		sort.Strings(extras)
		return fmt.Errorf("ssm inventory association carries unknown parameters: %s", strings.Join(extras, ", "))
	}
	return nil
}
