// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	awsrds "github.com/aws/aws-sdk-go-v2/service/rds"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	awssecretsmanager "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	awsssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// listDynamoDB mirrors the in-tree dynamodb snapshot: table metadata only.
// Item values, stream records, exports, and backups stay unread.
func listDynamoDB(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awsdynamodb.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	tables := awsdynamodb.NewListTablesPaginator(client, &awsdynamodb.ListTablesInput{})
	for tables.HasMorePages() {
		page, err := tables.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("dynamodb list tables: %w", err)
		}
		for _, name := range page.TableNames {
			described, err := client.DescribeTable(ctx, &awsdynamodb.DescribeTableInput{TableName: aws.String(name)})
			if err != nil {
				return nil, fmt.Errorf("dynamodb describe table: %w", err)
			}
			if described.Table == nil {
				continue
			}
			records = append(records, record(aws.ToString(described.Table.TableArn), "dynamodb", region, aws.ToString(described.Table.TableName), "table"))
		}
	}
	return records, nil
}

// listRDS mirrors the in-tree rds scanner: DB instances, clusters, and
// subnet groups as metadata-only records. Database contents, snapshots, and
// connection secrets stay unread.
func listRDS(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awsrds.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	instances := awsrds.NewDescribeDBInstancesPaginator(client, &awsrds.DescribeDBInstancesInput{})
	for instances.HasMorePages() {
		page, err := instances.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("rds describe DB instances: %w", err)
		}
		for _, instance := range page.DBInstances {
			records = append(records, record(aws.ToString(instance.DBInstanceArn), "rds", region, aws.ToString(instance.DBInstanceIdentifier), "db-instance"))
		}
	}
	clusters := awsrds.NewDescribeDBClustersPaginator(client, &awsrds.DescribeDBClustersInput{})
	for clusters.HasMorePages() {
		page, err := clusters.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("rds describe DB clusters: %w", err)
		}
		for _, cluster := range page.DBClusters {
			records = append(records, record(aws.ToString(cluster.DBClusterArn), "rds", region, aws.ToString(cluster.DBClusterIdentifier), "db-cluster"))
		}
	}
	subnets := awsrds.NewDescribeDBSubnetGroupsPaginator(client, &awsrds.DescribeDBSubnetGroupsInput{})
	for subnets.HasMorePages() {
		page, err := subnets.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("rds describe DB subnet groups: %w", err)
		}
		for _, group := range page.DBSubnetGroups {
			records = append(records, record(aws.ToString(group.DBSubnetGroupArn), "rds", region, aws.ToString(group.DBSubnetGroupName), "db-subnet-group"))
		}
	}
	return records, nil
}

// listS3 mirrors the in-tree s3 scanner's bucket inventory: control-plane
// metadata only. Object contents, policy documents, ACL grants, and
// notification payloads stay unread.
func listS3(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awss3.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	buckets := awss3.NewListBucketsPaginator(client, &awss3.ListBucketsInput{})
	for buckets.HasMorePages() {
		page, err := buckets.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("s3 list buckets: %w", err)
		}
		for _, bucket := range page.Buckets {
			name := aws.ToString(bucket.Name)
			records = append(records, record("arn:aws:s3:::"+name, "s3", region, name, "bucket"))
		}
	}
	return records, nil
}

// listSecretsManager mirrors the in-tree secretsmanager scanner: secret
// metadata only. Secret values and version payloads stay unread.
func listSecretsManager(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awssecretsmanager.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	secrets := awssecretsmanager.NewListSecretsPaginator(client, &awssecretsmanager.ListSecretsInput{})
	for secrets.HasMorePages() {
		page, err := secrets.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("secretsmanager list secrets: %w", err)
		}
		for _, secret := range page.SecretList {
			records = append(records, record(aws.ToString(secret.ARN), "secretsmanager", region, aws.ToString(secret.Name), "secret"))
		}
	}
	return records, nil
}

// listSSM mirrors the in-tree ssm scanner: parameter metadata only.
// Parameter values, history values, and policy JSON stay unread.
func listSSM(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awsssm.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	parameters := awsssm.NewDescribeParametersPaginator(client, &awsssm.DescribeParametersInput{})
	for parameters.HasMorePages() {
		page, err := parameters.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ssm describe parameters: %w", err)
		}
		for _, parameter := range page.Parameters {
			records = append(records, record("", "ssm", region, aws.ToString(parameter.Name), "parameter"))
		}
	}
	return records, nil
}
