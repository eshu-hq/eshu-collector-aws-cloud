// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"net/url"
	"strings"
)

func checkSourceURI(raw string) error {
	trimmed := strings.TrimSpace(raw)
	lower := strings.ToLower(trimmed)
	// Parse once so percent-encoded signing keys cannot bypass the raw-text
	// guard. Do not wrap parse errors: a source URI may contain credentials.
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("source URI is invalid or embeds credentials")
	}
	// Opaque URIs can hide userinfo in their body, outside parsed.User.
	if parsed.User != nil || (strings.Contains(trimmed, "@") && !strings.Contains(lower, "://")) {
		return fmt.Errorf("source URI must not embed credentials")
	}
	if parsed.RawQuery != "" {
		values, err := url.ParseQuery(parsed.RawQuery)
		if err != nil {
			return fmt.Errorf("source URI is invalid or embeds credentials")
		}
		for key := range values {
			if unsafeSourceQueryKey(key) {
				return fmt.Errorf("source URI must not embed credentials")
			}
		}
	}
	for _, key := range []string{"password", "secret", "token", "credential", "signature", "accesskeyid"} {
		if strings.Contains(lower, key+"=") {
			return fmt.Errorf("source URI must not embed credentials")
		}
	}
	return nil
}

func unsafeSourceQueryKey(key string) bool {
	lower := strings.ToLower(key)
	for _, marker := range []string{"password", "secret", "token", "credential", "signature", "accesskeyid"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
