// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

// loaders is the production service registry: every allowed_services name
// resolves to the live reader that mirrors the in-tree scanner's read
// surface for that service. Test fakes replace Collector.Loaders instead of
// this table.
var loaders = map[string]Loader{
	"apigateway":     listAPIGateway,
	"cloudfront":     listCloudFront,
	"cloudwatchlogs": listCloudWatchLogs,
	"dynamodb":       listDynamoDB,
	"ec2":            listEC2,
	"ecr":            listECR,
	"ecs":            listECS,
	"eks":            listEKS,
	"elbv2":          listELBV2,
	"eventbridge":    listEventBridge,
	"iam":            listIAM,
	"lambda":         listLambda,
	"rds":            listRDS,
	"route53":        listRoute53,
	"s3":             listS3,
	"secretsmanager": listSecretsManager,
	"sns":            listSNS,
	"sqs":            listSQS,
	"ssm":            listSSM,
}

// globalServices are account-global APIs: listing them once (in the first
// configured region) covers the account, and repeating them per region would
// only duplicate records the Collect dedup would collapse anyway.
var globalServices = map[string]bool{
	"cloudfront": true,
	"iam":        true,
	"route53":    true,
	"s3":         true,
}
