// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AssumeScopeRole exchanges ambient credentials for a scope role through STS
// AssumeRole with the scope external ID. It returns a copy of the base config
// that issues every service call with short-lived assumed credentials; the
// ambient credentials never leave the host. No static credential material is
// accepted anywhere on this path: the role ARN and external ID are
// identifiers, not secrets, and the issued session credentials live only in
// memory for the claim. Callers keep the existing identity-match check, which
// fails the claim when the assumed account is not the scope account.
func AssumeScopeRole(ctx context.Context, base aws.Config, roleARN, externalID string) (aws.Config, error) {
	if roleARN == "" || externalID == "" {
		return aws.Config{}, fmt.Errorf("assume scope role needs a role ARN and external ID")
	}
	stsClient := sts.NewFromConfig(base)
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
		o.ExternalID = aws.String(externalID)
		o.RoleSessionName = "eshu-collector-scope-read"
	})
	assumed := base
	assumed.Credentials = aws.NewCredentialsCache(provider)
	return assumed, nil
}
