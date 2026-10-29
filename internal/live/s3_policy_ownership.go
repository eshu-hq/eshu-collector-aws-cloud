// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// readS3PolicyAndOwnership records only the policy status boolean and ownership
// enum values. A missing policy has unknown public status; denied reads fail.
func readS3PolicyAndOwnership(ctx context.Context, api s3BucketDetailsAPI, name, accountID string) (map[string]any, error) {
	policy, err := api.GetBucketPolicyStatus(ctx, &awss3.GetBucketPolicyStatusInput{
		Bucket: aws.String(name), ExpectedBucketOwner: aws.String(accountID),
	})
	if err != nil {
		if !isMissingS3Configuration(err, "NoSuchBucketPolicy") {
			return nil, fmt.Errorf("s3 get bucket policy status %q: %w", name, err)
		}
		policy = nil
	}
	attrs := map[string]any{"policy_is_public": nil, "ownership_controls": []string{}}
	if policy != nil && policy.PolicyStatus != nil {
		attrs["policy_is_public"] = optionalS3Bool(policy.PolicyStatus.IsPublic)
	}
	ownership, err := api.GetBucketOwnershipControls(ctx, &awss3.GetBucketOwnershipControlsInput{
		Bucket: aws.String(name), ExpectedBucketOwner: aws.String(accountID),
	})
	if err != nil {
		if !isMissingS3Configuration(err, "OwnershipControlsNotFoundError") {
			return nil, fmt.Errorf("s3 get bucket ownership controls %q: %w", name, err)
		}
		ownership = nil
	}
	if ownership != nil && ownership.OwnershipControls != nil {
		values := []string{}
		for _, rule := range ownership.OwnershipControls.Rules {
			if value := strings.TrimSpace(string(rule.ObjectOwnership)); value != "" {
				values = append(values, value)
			}
		}
		attrs["ownership_controls"] = values
	}
	return attrs, nil
}

func isMissingS3Configuration(err error, code string) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == code
}
