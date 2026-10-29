// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"
	"unicode"

	"github.com/eshu-hq/eshu-sdk/collector/marker"
)

const awsRedactionRuleset = "aws-launch-2026-05-14"

// This is the AWS launch policy from the legacy scanner. Classification is
// private to AWS; the SDK marker package owns only the keyed digest framing.
var awsSensitiveKeys = map[string]struct{}{
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

func redactAWSString(raw, source string, key marker.Key) map[string]any {
	source = strings.TrimSpace(source)
	if source == "" {
		source = "unknown"
	}
	reason := "unknown_provider_schema"
	if awsSensitiveSource(source) {
		reason = "known_sensitive_key"
	}
	value := marker.String(raw, reason, source, key)
	return map[string]any{
		"marker": value.Marker, "reason": value.Reason,
		"source": value.Source, "ruleset_version": awsRedactionRuleset,
	}
}

func awsSensitiveSource(source string) bool {
	if _, ok := awsSensitiveKeys[normalizeAWSKey(source)]; ok {
		return true
	}
	for _, segment := range strings.FieldsFunc(source, func(r rune) bool {
		return r == '.' || r == '/' || r == '[' || r == ']'
	}) {
		if _, ok := awsSensitiveKeys[normalizeAWSKey(strings.TrimSpace(segment))]; ok {
			return true
		}
	}
	return false
}

// normalizeAWSKey retains the legacy policy's Unicode and camel-case rules.
func normalizeAWSKey(value string) string {
	var builder strings.Builder
	runes := []rune(strings.TrimSpace(value))
	lastUnderscore := false
	var previous rune
	for index, current := range runes {
		if current == '-' || current == '.' || current == '/' || current == '[' || current == ']' || unicode.IsSpace(current) {
			writeAWSUnderscore(&builder, &lastUnderscore)
			previous = current
			continue
		}
		var next rune
		if index+1 < len(runes) {
			next = runes[index+1]
		}
		if unicode.IsUpper(current) && (unicode.IsLower(previous) || unicode.IsDigit(previous) || (unicode.IsUpper(previous) && unicode.IsLower(next))) {
			writeAWSUnderscore(&builder, &lastUnderscore)
		}
		builder.WriteRune(unicode.ToLower(current))
		lastUnderscore = false
		previous = current
	}
	return strings.Trim(builder.String(), "_")
}

func writeAWSUnderscore(builder *strings.Builder, last *bool) {
	if builder.Len() > 0 && !*last {
		builder.WriteByte('_')
		*last = true
	}
}
