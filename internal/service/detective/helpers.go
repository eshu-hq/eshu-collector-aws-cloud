// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package detective

import "strings"

// memberResourceID derives a member-account resource id from the graph ARN and
// the account id. Keying on these two stable values, never on list order, keeps
// the identity constant across scans even when Detective reorders members.

// graphName derives a stable display name from a behavior graph ARN. The
// Detective graph ARN ends in graph:<id>, so the trailing id is the most
// human-meaningful name; the full ARN is the fallback.

// graphDatasourcePackages returns the sorted, de-duplicated union of the
// data-source package names enabled across a graph's members. It is an
// aggregate identity signal (for example DETECTIVE_CORE, which ingests
// GuardDuty); no usage volume or finding content is included.

// graphSourcesGuardDuty reports whether the graph is known to ingest GuardDuty
// data. It is true when a resolver supplied a GuardDuty detector id or when any
// member enables the DETECTIVE_CORE package, which ingests GuardDuty findings.

// datasourcePackageDetectiveCore is the Detective data-source package that
// ingests GuardDuty findings. It is matched case-insensitively so a future SDK
// casing change does not silently drop the GuardDuty-source signal.

// cloneStringMap copies a tag map, trimming blank keys, so the scanner does not
// alias the caller's map or carry empty keys.
func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		output[trimmed] = value
	}
	if len(output) == 0 {
		return nil
	}
	return output
}

// cloneStringSlice copies a string slice, trimming blanks, so attribute values
// do not alias the source slice.

// sortStrings sorts a string slice in place with a small insertion sort, keeping
// the package free of an import for one short, deterministic ordering.
