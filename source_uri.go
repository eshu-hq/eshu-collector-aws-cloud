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
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(strings.ToLower(trimmed), "file:") {
		return fmt.Errorf("source URI must not contain host-local paths")
	}
	if known, safe := fastPlainHTTPS(raw); known {
		if safe {
			return nil
		}
		return fmt.Errorf("source URI must not embed credentials")
	}
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
	for _, key := range []string{"password", "secret", "token", "credential", "signature", "accesskeyid", "apikey", "api_key", "api-key", "authorization"} {
		if strings.Contains(lower, key+"=") {
			return fmt.Errorf("source URI must not embed credentials")
		}
	}
	return nil
}

func unsafeSourceQueryKey(key string) bool {
	lower := strings.ToLower(key)
	for _, marker := range []string{"password", "secret", "token", "credential", "signature", "accesskeyid", "apikey", "api_key", "api-key", "authorization"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// fastPlainHTTPS accepts only a conservative ASCII subset. Everything else
// uses the original URL parser and query parser.
func fastPlainHTTPS(raw string) (bool, bool) {
	if !strings.HasPrefix(raw, "https://") {
		return false, false
	}
	rest := raw[len("https://"):]
	end := strings.IndexAny(rest, "/?")
	host := rest
	if end >= 0 {
		host = rest[:end]
	}
	if host == "" {
		return false, false
	}
	for _, c := range host {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false, false
		}
	}
	suffix := rest[len(host):]
	for _, c := range suffix {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == '~' || c == '/' || c == '?' || c == '=' || c == '&') {
			return false, false
		}
	}
	_, query, hasQuery := strings.Cut(suffix, "?")
	if hasQuery {
		for query != "" {
			var item string
			item, query, _ = strings.Cut(query, "&")
			key, _, _ := strings.Cut(item, "=")
			if unsafeSourceQueryKey(key) {
				return true, false
			}
		}
	}
	lower := strings.ToLower(raw)
	for _, key := range []string{"password", "secret", "token", "credential", "signature", "accesskeyid", "apikey", "api_key", "api-key", "authorization"} {
		if strings.Contains(lower, key+"=") {
			return true, false
		}
	}
	return true, true
}
