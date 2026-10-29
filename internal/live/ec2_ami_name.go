// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"
	"unicode"
	"unicode/utf8"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// amiNameDropCause names why one DescribeImages Name value was dropped. Causes
// stay in unit tests and code review: scan diagnostics carry the effect and
// the dropped count only, never a per-name cause or the raw text.
type amiNameDropCause string

const (
	// amiNameDropLength marks a present name outside the 3-128 rune AWS
	// CreateImage bound.
	amiNameDropLength amiNameDropCause = "length"
	// amiNameDropHygiene marks a name the hygiene scan tripped: the
	// satellite-local credential pattern or a key=value pair whose key the
	// shared sensitive-name predicate flags.
	amiNameDropHygiene amiNameDropCause = "hygiene"
	// amiNameDropCharset marks a name outside the exact AWS CreateImage
	// charset, or one carrying a control character.
	amiNameDropCharset amiNameDropCause = "charset"
)

// amiNameResult is the verdict for one DescribeImages Name value. Exactly one
// of admit, omit, drop holds: admitted values pass verbatim, blank values stay
// omitted with no warning (absent or blank values remain omitted per the #9301
// agreement), and dropped values warn once per scan with the
// ami_name_dropped effect.
type amiNameResult struct {
	value string
	admit bool
	omit  bool
	drop  bool
	cause amiNameDropCause
}

// inspectAMIName validates one DescribeImages Name value under the
// eshu-hq/eshu#9525 conditional admission: JSON scalar string by construction
// (the AWS SDK surfaces Name as *string; the producer never stringifies
// another type into this field), 3-128 runes, the exact AWS CreateImage
// charset, and the hygiene scan. Any failure drops the field only — the AMI
// keeps its id and all seven typed fields — and never truncates: a shortened
// name is a name AWS never reported.
//
// The admitted value is untrusted creator-controlled text. Admission claims
// structural validity only, never secret-freedom: a patternless token fits the
// charset and passes (pinned by TestAMINameBareTokenPassesDocumented).
func inspectAMIName(name string) amiNameResult {
	if strings.TrimSpace(name) == "" {
		return amiNameResult{omit: true}
	}
	if n := utf8.RuneCountInString(name); n < 3 || n > 128 {
		return amiNameResult{drop: true, cause: amiNameDropLength}
	}
	// The hygiene gate runs before the shape gate so the content check, not
	// the charset, owns secret-shaped text. Both fail closed; the observable
	// outcome is identical either way (drop the field, warn once per scan).
	if collector.ContainsCredentialText(name) || amiNamePairSensitive(name) {
		return amiNameResult{drop: true, cause: amiNameDropHygiene}
	}
	if !amiNameCharsetOK(name) {
		return amiNameResult{drop: true, cause: amiNameDropCharset}
	}
	return amiNameResult{value: name, admit: true}
}

// amiNameCharsetOK reports whether every rune of value fits the exact AWS
// CreateImage Name charset: alphanumerics plus `()[] ./-'@_`. The set holds
// printable ASCII only, so the explicit control rejection below documents the
// no-controls rule rather than adding to it.
func amiNameCharsetOK(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			strings.ContainsRune("()[] ./-'@_", r):
			continue
		default:
			return false
		}
	}
	return true
}

// amiNamePairSensitive is the satellite-local equivalent of the urlredact
// FreeText walk, reduced to a drop trigger for a single name value: it reports
// whether value carries a "key=value" or "key: value" pair whose key the
// shared sensitive-name predicate flags. The shared predicate is called
// as-is — never narrowed, never widened — and no value inspection or entropy
// check exists. Quotes and spaces around the separator are skipped, matching
// the FreeText rule; percent-encoded separators are out of scope (a `%` fails
// the charset, and names are single values, not URLs or prose).
func amiNamePairSensitive(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] != '=' && value[i] != ':' {
			continue
		}
		left := i - 1
		for left >= 0 && (value[left] == ' ' || value[left] == '\t' || value[left] == '"' || value[left] == '\'') {
			left--
		}
		end := left + 1
		for left >= 0 && isAMINamePairTokenByte(value[left]) {
			left--
		}
		if token := value[left+1 : end]; token != "" && sdk.IsSensitiveKeyName(token) {
			return true
		}
	}
	return false
}

// isAMINamePairTokenByte reports whether b can sit inside the key half of a
// key=value pair: letters, digits, and the `_`, `.`, `-` joins real credential
// names use. The separators themselves never belong to a key.
func isAMINamePairTokenByte(b byte) bool {
	return b >= 'a' && b <= 'z' ||
		b >= 'A' && b <= 'Z' ||
		b >= '0' && b <= '9' ||
		b == '_' || b == '.' || b == '-'
}
