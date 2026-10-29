// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-sdk/collector/marker"
)

// listECS reads ECS clusters, services, tasks, and distinct task definitions.
// Service-referenced revisions are described even when the active list omits them.
func listECS(ctx context.Context, cfg aws.Config, key marker.Key) ([]collector.Record, error) {
	if key.IsZero() {
		return nil, fmt.Errorf("live ecs requires ESHU_AWS_REDACTION_KEY")
	}
	client := awsecs.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	seenDefinitions := make(map[string]struct{})
	clusters := awsecs.NewListClustersPaginator(client, &awsecs.ListClustersInput{})
	for clusters.HasMorePages() {
		page, err := clusters.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ecs list clusters: %w", err)
		}
		for _, arn := range page.ClusterArns {
			described, err := client.DescribeClusters(ctx, ecsClusterDescribeInput(arn))
			if err != nil {
				return nil, fmt.Errorf("ecs describe clusters: %w", err)
			}
			for _, cluster := range described.Clusters {
				row := ecsClusterRecord(cluster, region)
				if row.Resource == nil {
					return nil, fmt.Errorf("ecs described cluster has no ARN")
				}
				records = append(records, row)
			}
			services := awsecs.NewListServicesPaginator(client, &awsecs.ListServicesInput{Cluster: aws.String(arn)})
			for services.HasMorePages() {
				servicePage, err := services.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("ecs list services: %w", err)
				}
				for _, chunk := range chunks(servicePage.ServiceArns, 10) {
					described, err := client.DescribeServices(ctx, ecsServiceDescribeInput(arn, chunk))
					if err != nil {
						return nil, fmt.Errorf("ecs describe services: %w", err)
					}
					for _, service := range described.Services {
						row := ecsServiceRecord(service, region)
						if row.Resource == nil {
							return nil, fmt.Errorf("ecs described service has no ARN")
						}
						records = append(records, row)
						records, err = collectECSTaskDefinition(ctx, client, records, aws.ToString(service.TaskDefinition), region, seenDefinitions, key)
						if err != nil {
							return nil, err
						}
					}
				}
			}
			tasks := awsecs.NewListTasksPaginator(client, &awsecs.ListTasksInput{Cluster: aws.String(arn)})
			for tasks.HasMorePages() {
				taskPage, err := tasks.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("ecs list tasks: %w", err)
				}
				for _, chunk := range chunks(taskPage.TaskArns, 100) {
					described, err := client.DescribeTasks(ctx, &awsecs.DescribeTasksInput{Cluster: aws.String(arn), Tasks: chunk})
					if err != nil {
						return nil, fmt.Errorf("ecs describe tasks: %w", err)
					}
					for _, task := range described.Tasks {
						row := ecsTaskRecord(task, region)
						if row.Resource == nil {
							return nil, fmt.Errorf("ecs described task has no ARN")
						}
						records = append(records, row)
					}
				}
			}
		}
	}
	definitions := awsecs.NewListTaskDefinitionsPaginator(client, &awsecs.ListTaskDefinitionsInput{})
	for definitions.HasMorePages() {
		page, err := definitions.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ecs list task definitions: %w", err)
		}
		for _, arn := range page.TaskDefinitionArns {
			records, err = collectECSTaskDefinition(ctx, client, records, arn, region, seenDefinitions, key)
			if err != nil {
				return nil, err
			}
		}
	}
	return records, nil
}

// collectECSTaskDefinition describes one previously unseen definition ARN.
func collectECSTaskDefinition(ctx context.Context, client *awsecs.Client, records []collector.Record, arn, region string, seen map[string]struct{}, key marker.Key) ([]collector.Record, error) {
	arn = strings.TrimSpace(arn)
	if arn == "" {
		return records, nil
	}
	if _, exists := seen[arn]; exists {
		return records, nil
	}
	described, err := client.DescribeTaskDefinition(ctx, ecsTaskDefinitionDescribeInput(arn))
	if err != nil {
		return nil, sensitiveReadError("ecs describe task definition", err)
	}
	if described == nil || described.TaskDefinition == nil {
		return nil, fmt.Errorf("ecs described task definition has no body")
	}
	row := ecsTaskDefinitionRecord(arn, *described.TaskDefinition, described.Tags, region, key)
	if row.Resource == nil {
		return nil, fmt.Errorf("ecs described task definition has no matching ARN")
	}
	seen[arn] = struct{}{}
	return append(records, row), nil
}
