// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"strings"
	"testing"
)

func TestSourceURIQuerySafety(t *testing.T) {
	t.Parallel()

	for _, marker := range []string{"password", "secret", "token", "credential", "signature", "accesskeyid", "apikey", "api_key", "api-key", "authorization"} {
		for _, key := range []string{marker, strings.ToUpper(marker), "x-" + marker} {
			for _, suffix := range []string{"", "=private-value"} {
				uri := "https://example.invalid/resource?" + key + suffix
				if err := checkSourceURI(uri); err == nil {
					t.Errorf("credential query key %q accepted", key)
				} else if strings.Contains(err.Error(), "private-value") {
					t.Errorf("error exposed query value: %v", err)
				}
			}
		}
	}

	for _, uri := range []string{
		"https://example.invalid/resource?%54oken=private-value",
		"https://example.invalid/resource?mode=%xx",
		"https://example.invalid/resource?mode=one;other=two",
		"https://user:private-value@example.invalid/resource",
		"aws:private-value@example.invalid/resource",
		"file:///private/path",
		"/private/path",
		"https://example.invalid/resource#token=private-value",
	} {
		if err := checkSourceURI(uri); err == nil {
			t.Errorf("unsafe URI %q accepted", uri)
		} else if strings.Contains(err.Error(), "private-value") {
			t.Errorf("error exposed credential material: %v", err)
		}
	}

	for _, uri := range []string{
		"https://example.invalid/resource?region=us-east-1&mode=read",
		"https://example.invalid/resource?mode=read&mode=write",
		"https://example.invalid/resource?mode=read%20only",
		"https://example.invalid/resource#section",
		"aws:ec2:resource/example",
	} {
		if err := checkSourceURI(uri); err != nil {
			t.Errorf("safe URI %q refused: %v", uri, err)
		}
	}
}
