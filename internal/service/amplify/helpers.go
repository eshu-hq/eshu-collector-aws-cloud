// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package amplify

import (
	"net/url"
	"strings"
)

// cloudFrontDomainSuffix is the public DNS suffix of every CloudFront
// distribution domain. Amplify subdomain DNS records that point at CloudFront
// end in this suffix, so the app->CloudFront edge only fires when the record
// resolves to a *.cloudfront.net host.
const cloudFrontDomainSuffix = ".cloudfront.net"

// SanitizeRepositoryURL reduces an Amplify repository URL to scheme, host, and
// path only, dropping any embedded userinfo (a token-bearing
// https://x-access-token:TOKEN@github.com/... form) and any query or fragment.
// A token must never reach a fact payload or a graph join key. For non-URL
// values that do not parse as an absolute URL (scp-style
// git@github.com:org/repo.git) it strips any leading "<user>@" segment, so
// "git@github.com:org/repo.git" becomes "github.com:org/repo.git", dropping a
// user component that could carry a token while preserving the host and path.
// Values without an "@" are returned trimmed and otherwise unchanged. It is
// exported so the SDK adapter strips the token at the boundary, before the raw
// URL reaches a scanner-owned record.
func SanitizeRepositoryURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		// Not a parseable absolute URL (for example an scp-style git address).
		// Strip any userinfo@ segment defensively without inventing structure.
		if at := strings.LastIndex(raw, "@"); at >= 0 && !strings.Contains(raw, "://") {
			return strings.TrimSpace(raw[at+1:])
		}
		return raw
	}
	rebuilt := &url.URL{
		Scheme: parsed.Scheme,
		Host:   parsed.Host,
		Path:   parsed.Path,
	}
	return rebuilt.String()
}

// cloudFrontDomainFromDNSRecord extracts the CloudFront distribution domain
// (the *.cloudfront.net host) from an Amplify subdomain DNS record. The record
// is published as a CNAME, sometimes with a leading "CNAME " type token or a
// trailing dot. It returns the empty string when the record does not resolve to
// a CloudFront host so the app->CloudFront edge never dangles against a non-edge
// target.
func cloudFrontDomainFromDNSRecord(record string) string {
	record = strings.TrimSpace(record)
	if record == "" {
		return ""
	}
	// Amplify formats the record as "<type> <value>" (for example
	// "CNAME d123.cloudfront.net"); take the last whitespace-separated field.
	if fields := strings.Fields(record); len(fields) > 0 {
		record = fields[len(fields)-1]
	}
	record = strings.TrimSuffix(strings.ToLower(record), ".")
	if strings.HasSuffix(record, cloudFrontDomainSuffix) {
		return record
	}
	return ""
}
