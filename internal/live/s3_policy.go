// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

type s3PolicyFlags struct {
	present      *bool
	public       *bool
	crossAccount *bool
}

// readS3BucketPolicyFlags derives only metadata from a transient policy body.
// Missing policy is known absent, while an empty successful response is unknown.
// Unexpected errors stop the S3 read without exposing AWS response contents.
func readS3BucketPolicyFlags(ctx context.Context, api s3BucketDetailsAPI, name, accountID string) (s3PolicyFlags, error) {
	output, err := api.GetBucketPolicy(ctx, &awss3.GetBucketPolicyInput{
		Bucket: aws.String(name), ExpectedBucketOwner: aws.String(accountID),
	})
	if err != nil {
		if isMissingS3Configuration(err, "NoSuchBucketPolicy") {
			absent := false
			return s3PolicyFlags{present: &absent}, nil
		}
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			switch apiErr.ErrorCode() {
			case "AccessDenied", "AccessDeniedException":
				return s3PolicyFlags{}, fmt.Errorf("s3 get bucket policy %q: access denied", name)
			case "Throttling", "ThrottlingException", "SlowDown":
				return s3PolicyFlags{}, fmt.Errorf("s3 get bucket policy %q: throttled", name)
			}
		}
		return s3PolicyFlags{}, fmt.Errorf("s3 get bucket policy %q: read failed", name)
	}
	if output == nil || strings.TrimSpace(aws.ToString(output.Policy)) == "" {
		return s3PolicyFlags{}, nil
	}
	public, crossAccount, ok := deriveS3PolicyFlags(aws.ToString(output.Policy), accountID)
	if !ok {
		return s3PolicyFlags{}, fmt.Errorf("s3 get bucket policy %q: invalid policy document", name)
	}
	present := true
	return s3PolicyFlags{present: &present, public: &public, crossAccount: &crossAccount}, nil
}

// deriveS3PolicyFlags mirrors the legacy adapter's Allow/AWS-principal rules.
// A condition can only restrict access, so a wildcard remains conservatively
// marked as a grant. Raw policy text and principal values never leave this call.
func deriveS3PolicyFlags(document, owner string) (public, crossAccount, ok bool) {
	raw := strings.TrimSpace(document)
	if decoded, err := url.QueryUnescape(raw); err == nil && strings.Contains(decoded, "{") {
		raw = decoded
	}
	var policy struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(raw), &policy) != nil || len(policy.Statement) == 0 {
		return false, false, false
	}
	var statements []struct {
		Effect       string          `json:"Effect"`
		Principal    json.RawMessage `json:"Principal"`
		NotPrincipal json.RawMessage `json:"NotPrincipal"`
	}
	if policy.Statement[0] == '[' {
		if json.Unmarshal(policy.Statement, &statements) != nil {
			return false, false, false
		}
	} else {
		var statement struct {
			Effect       string          `json:"Effect"`
			Principal    json.RawMessage `json:"Principal"`
			NotPrincipal json.RawMessage `json:"NotPrincipal"`
		}
		if json.Unmarshal(policy.Statement, &statement) != nil {
			return false, false, false
		}
		statements = append(statements, statement)
	}
	if len(statements) == 0 {
		return false, false, false
	}
	for _, statement := range statements {
		if strings.EqualFold(strings.TrimSpace(statement.Effect), "Deny") {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(statement.Effect), "Allow") || len(statement.NotPrincipal) > 0 {
			return false, false, false
		}
		principals, valid := s3AWSPrincipals(statement.Principal)
		if !valid {
			return false, false, false
		}
		for _, principal := range principals {
			identifier := strings.TrimSpace(principal)
			if identifier == "*" {
				public = true
			} else if account := s3PrincipalAccount(identifier); account != "" {
				if owner != "" && account != owner {
					crossAccount = true
				}
			} else {
				return false, false, false
			}
		}
	}
	return public, crossAccount, true
}

func s3AWSPrincipals(raw json.RawMessage) ([]string, bool) {
	if values, ok := s3PolicyStrings(raw); ok {
		return values, true
	}
	var principals map[string]json.RawMessage
	if json.Unmarshal(raw, &principals) != nil || len(principals) == 0 {
		return nil, false
	}
	var awsPrincipals []string
	for key, value := range principals {
		switch key {
		case "AWS", "Service", "Federated", "CanonicalUser":
			values, ok := s3PolicyStrings(value)
			if !ok {
				return nil, false
			}
			if key == "AWS" {
				awsPrincipals = values
			}
		default:
			return nil, false
		}
	}
	return awsPrincipals, true
}

func s3PolicyStrings(raw json.RawMessage) ([]string, bool) {
	var one string
	if json.Unmarshal(raw, &one) == nil && strings.TrimSpace(one) != "" {
		return []string{one}, true
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil && len(many) > 0 {
		for _, value := range many {
			if strings.TrimSpace(value) == "" {
				return nil, false
			}
		}
		return many, true
	}
	return nil, false
}

func s3PrincipalAccount(identifier string) string {
	if s3AccountID(identifier) {
		return identifier
	}
	if !strings.HasPrefix(identifier, "arn:") {
		return ""
	}
	parts := strings.SplitN(identifier, ":", 6)
	if len(parts) == 6 && s3AccountID(parts[4]) {
		return parts[4]
	}
	return ""
}

func s3AccountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
