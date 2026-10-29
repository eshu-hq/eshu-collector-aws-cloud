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
func listS3(ctx context.Context, cfg aws.Config, identity VerifiedIdentity) ([]collector.Record, error) {
	return listS3WithAPI(ctx, awss3.NewFromConfig(cfg), cfg.Region, identity)
}

func listS3WithAPI(ctx context.Context, client s3BucketAPI, region string, identity VerifiedIdentity) ([]collector.Record, error) {
	input, err := s3ListInput(region)
	if err != nil {
		return nil, err
	}
	records := []collector.Record{}
	denials := []optionalDenial{}
	buckets := awss3.NewListBucketsPaginator(client, input)
	for buckets.HasMorePages() {
		page, err := buckets.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("s3 list buckets: %w", err)
		}
		for _, bucket := range page.Buckets {
			if aws.ToString(bucket.Name) == "" {
				continue
			}
			headRegion, tags, err := readS3BucketDetails(ctx, client, aws.ToString(bucket.Name), identity.AccountID)
			if err != nil {
				return nil, err
			}
			if headRegion != "" && headRegion != region {
				return nil, fmt.Errorf("s3 HeadBucket returned a bucket outside the claimed region")
			}
			row, err := s3BucketRecord(bucket, region, identity)
			if err != nil {
				return nil, err
			}
			row.Resource.Tags = tags
			posture, err := readS3BucketPosture(ctx, client, aws.ToString(bucket.Name), identity.AccountID)
			if err != nil {
				return nil, err
			}
			for key, value := range posture {
				row.Resource.Attributes[key] = value
			}
			policyAndOwnership, err := readS3PolicyAndOwnership(ctx, client, aws.ToString(bucket.Name), identity.AccountID)
			if err != nil {
				return nil, err
			}
			for key, value := range policyAndOwnership {
				row.Resource.Attributes[key] = value
			}
			websiteLogging, loggingObserved, err := readS3WebsiteLogging(ctx, client, aws.ToString(bucket.Name), identity.AccountID)
			if err != nil {
				return nil, err
			}
			for key, value := range websiteLogging {
				row.Resource.Attributes[key] = value
			}
			replication, err := readS3Replication(ctx, client, aws.ToString(bucket.Name), identity.AccountID)
			if err != nil {
				return nil, err
			}
			row.S3Posture = &collector.S3BucketPostureObservation{
				Boundary:  collector.Boundary{Region: region, ServiceKind: "s3"},
				BucketARN: row.Resource.ARN, BucketName: aws.ToString(bucket.Name),
				ReplicationEnabled: replication, SourceRecordID: row.Resource.ARN + "#posture",
			}
			applyS3KnownPosture(row.S3Posture, posture, policyAndOwnership, websiteLogging, loggingObserved)
			encryption, denied, err := readS3BucketEncryption(ctx, client, aws.ToString(bucket.Name), identity.AccountID)
			if err != nil {
				return nil, err
			}
			if denied {
				denials = append(denials, optionalDenial{operation: "GetBucketEncryption", resource: "bucket:" + aws.ToString(bucket.Name), effect: "encryption-unknown"})
			} else {
				applyS3EncryptionPosture(row.S3Posture, encryption)
				for key, value := range encryption {
					row.Resource.Attributes[key] = value
				}
			}
			records = append(records, row)
		}
	}
	if len(denials) > 0 {
		return records, &optionalReadDenied{denials: denials}
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
