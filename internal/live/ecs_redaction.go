// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"
	"unicode"

	"github.com/eshu-hq/eshu-sdk/collector/marker"
)

// ecsRedactionRuleset identifies the AWS launch sensitive-key policy attached
// to redacted fact payload values. It mirrors the in-tree awscloud launch
// policy version so downstream proof can join on one policy identity.
const ecsRedactionRuleset = "aws-launch-2026-05-14"

// ecsSensitiveKeys is the membership policy for ECS environment sources. It
// mirrors the in-tree AWS launch key list exactly so classification agrees
// with the legacy scanner.
var ecsSensitiveKeys = map[string]struct{}{
	"access_key": {}, "access_key_id": {}, "api_key": {}, "apikey": {},
	"auth_token": {}, "authorization": {}, "aws_access_key_id": {},
	"aws_secret_access_key": {}, "aws_session_token": {}, "bearer_token": {},
	"client_secret": {}, "connection_string": {}, "credential": {},
	"credentials": {}, "database_url": {}, "db_password": {}, "db_url": {},
	"dsn": {}, "encryption_key": {}, "github_token": {}, "jdbc_url": {},
	"mongo_uri": {}, "passphrase": {}, "password": {}, "passwd": {},
	"private_key": {}, "pwd": {}, "redis_url": {}, "secret": {},
	"secret_access_key": {}, "secret_key": {}, "session_token": {},
	"signing_key": {}, "slack_webhook_url": {}, "stripe_secret_key": {},
	"token": {}, "webhook_url": {},
}

// redactECSEnvironmentValue replaces one container environment value with a
// keyed marker map. Values are always redacted (unknown provider schema);
// known sensitive key names carry the stronger reason label.
func redactECSEnvironmentValue(raw, source string, key marker.Key) map[string]any {
	source = strings.TrimSpace(source)
	if source == "" {
		source = "unknown"
	}
	reason := "unknown_provider_schema"
	if ecsSensitiveSource(source) {
		reason = "known_sensitive_key"
	}
	value := marker.String(raw, reason, source, key)
	return map[string]any{
		"marker": value.Marker, "reason": value.Reason,
		"source": value.Source, "ruleset_version": ecsRedactionRuleset,
	}
}

// ecsSensitiveSource reports whether the whole normalized source or any of
// its dot/slash/bracket segments matches the sensitive-key policy.
func ecsSensitiveSource(source string) bool {
	if _, ok := ecsSensitiveKeys[normalizeECSKey(source)]; ok {
		return true
	}
	for _, segment := range strings.FieldsFunc(source, func(r rune) bool {
		return r == '.' || r == '/' || r == '[' || r == ']'
	}) {
		if _, ok := ecsSensitiveKeys[normalizeECSKey(strings.TrimSpace(segment))]; ok {
			return true
		}
	}
	return false
}

// normalizeECSKey lowercases and folds separators and camel-case boundaries
// into underscores, matching the legacy policy's normalization.
func normalizeECSKey(value string) string {
	var builder strings.Builder
	runes := []rune(strings.TrimSpace(value))
	lastUnderscore := false
	var previous rune
	for index, current := range runes {
		if current == '-' || current == '.' || current == '/' || current == '[' || current == ']' || unicode.IsSpace(current) {
			if builder.Len() > 0 && !lastUnderscore {
				builder.WriteByte('_')
				lastUnderscore = true
			}
			previous = current
			continue
		}
		var next rune
		if index+1 < len(runes) {
			next = runes[index+1]
		}
		if unicode.IsUpper(current) && (unicode.IsLower(previous) || unicode.IsDigit(previous) || (unicode.IsUpper(previous) && unicode.IsLower(next))) {
			if builder.Len() > 0 && !lastUnderscore {
				builder.WriteByte('_')
			}
		}
		builder.WriteRune(unicode.ToLower(current))
		lastUnderscore = false
		previous = current
	}
	return strings.Trim(builder.String(), "_")
}
