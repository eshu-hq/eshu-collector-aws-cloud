// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// withoutIdentity adapts readers whose API does not need the verified caller
// identity. EC2 consumes it to construct resource ARNs.
func withoutIdentity(load func(context.Context, aws.Config) ([]collector.Record, error)) Loader {
	return func(ctx context.Context, cfg aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
		return load(ctx, cfg)
	}
}

// loaders is the production service registry: every allowed_services name
// resolves to the live reader that mirrors the in-tree scanner's read
// surface for that service. Test fakes replace Collector.Loaders instead of
// this table.
var loaders = map[string]Loader{
	"apigateway":     withoutIdentity(listAPIGateway),
	"cloudfront":     withoutIdentity(listCloudFront),
	"cloudwatchlogs": withoutIdentity(listCloudWatchLogs),
	"dynamodb":       withoutIdentity(listDynamoDB),
	"ec2":            listEC2,
	"ecr":            withoutIdentity(listECR),
	"ecs":            withoutIdentity(listECS),
	"eks":            listEKS,
	"elbv2":          withoutIdentity(listELBV2),
	"eventbridge":    withoutIdentity(listEventBridge),
	"iam":            listIAM,
	"lambda":         withoutIdentity(listLambda),
	"rds":            withoutIdentity(listRDS),
	"route53":        withoutIdentity(listRoute53),
	"s3":             listS3,
	"secretsmanager": withoutIdentity(listSecretsManager),
	"sns":            withoutIdentity(listSNS),
	"sqs":            withoutIdentity(listSQS),
	"ssm":            withoutIdentity(listSSM),
}

// globalServices are account-global APIs: listing them once (in the first
// configured region) covers the account, and repeating them per region would
// only duplicate records the Collect dedup would collapse anyway.
var globalServices = map[string]bool{
	"cloudfront": true,
	"iam":        true,
	"route53":    true,
}
