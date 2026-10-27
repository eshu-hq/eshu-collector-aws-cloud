// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

// loadAmbientConfig resolves region-scoped AWS config through the default
// credential chain only: environment, shared config, ECS/EKS container and
// EC2 instance roles, and IRSA web identity. It never installs static
// credentials, and no caller may add them: credential material stays in the
// platform, never in code, config, or payloads.
func loadAmbientConfig(ctx context.Context, region string) (aws.Config, error) {
	return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
}
