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

// scopeSessionName names every cross-account session the collector opens. A
// fixed name keeps CloudTrail attribution stable across regions and claims.
const scopeSessionName = "eshu-collector-scope-read"

// newSTSClient builds the STS client AssumeScopeRole exchanges through.
// Production passes sts.NewFromConfig; tests pass a constructor pointing a
// real client at a stub HTTP endpoint so the request is asserted end to end.
type newSTSClient func(aws.Config) *sts.Client

// AssumeScopeRole exchanges ambient credentials for a scope role through STS
// AssumeRole with the scope external ID. The exchange runs eagerly, so a
// denial fails the claim here with the role named instead of surfacing later
// as a generic verification error. It returns a copy of the base config that
// issues every service call with short-lived assumed credentials; the ambient
// credentials never leave the host. No static credential material is accepted
// anywhere on this path: the role ARN and external ID are identifiers, not
// secrets, and the issued session credentials live only in memory for the
// claim. Callers keep the existing identity-match check, which fails the
// claim when the assumed account is not the scope account.
func AssumeScopeRole(ctx context.Context, base aws.Config, roleARN, externalID string) (aws.Config, error) {
	if roleARN == "" || externalID == "" {
		return aws.Config{}, fmt.Errorf("assume scope role needs a role ARN and external ID")
	}
	return assumeWithClient(ctx, base, roleARN, externalID, func(cfg aws.Config) *sts.Client {
		return sts.NewFromConfig(cfg)
	})
}

// verifyError attributes an identity-check failure to the assume step when
// the scope was read with assumed credentials, so operators see which role
// produced unusable credentials instead of a generic verification message.
// Ambient scopes keep the historical message untouched.
func verifyError(region string, assumed bool, roleARN string, err error) error {
	if !assumed {
		return fmt.Errorf("%w for region %s", err, region)
	}
	return fmt.Errorf("%w for region %s after assuming %s", err, region, roleARN)
}

func assumeWithClient(ctx context.Context, base aws.Config, roleARN, externalID string, newClient newSTSClient) (aws.Config, error) {
	provider := stscreds.NewAssumeRoleProvider(newClient(base), roleARN, func(o *stscreds.AssumeRoleOptions) {
		o.ExternalID = aws.String(externalID)
		o.RoleSessionName = scopeSessionName
	})
	if _, err := provider.Retrieve(ctx); err != nil {
		return aws.Config{}, fmt.Errorf("assume role %s: %w", roleARN, err)
	}
	assumed := base
	assumed.Credentials = aws.NewCredentialsCache(provider)
	return assumed, nil
}
