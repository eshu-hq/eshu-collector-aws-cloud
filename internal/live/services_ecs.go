// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	awsecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-sdk/collector/marker"
)

// listECS reads ECS clusters, services, tasks, and distinct task definitions.
// Service-referenced revisions are described even when the active list omits them.
// Task-definition environment values are redacted with the key before any
// record is emitted, so a zero key fails before source acquisition.
func listECS(ctx context.Context, cfg aws.Config, key marker.Key) ([]collector.Record, error) {
	if key.IsZero() {
		return nil, fmt.Errorf("ecs list requires a redaction key before source acquisition")
	}
	client := awsecs.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	seenDefinitions := make(map[string]struct{})
	listedClusters := 0
	undescribedClusters := 0
	undescribedReasons := map[string]int{}
	listedServices, undescribedServices := 0, 0
	undescribedServiceReasons := map[string]int{}
	listedTasks, undescribedTasks := 0, 0
	undescribedTaskReasons := map[string]int{}
	clusters := awsecs.NewListClustersPaginator(client, &awsecs.ListClustersInput{})
	for clusters.HasMorePages() {
		page, err := clusters.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ecs list clusters: %w", err)
		}
		for _, arn := range page.ClusterArns {
			listedClusters++
			described, err := client.DescribeClusters(ctx, ecsClusterDescribeInput(arn))
			if err != nil {
				return nil, fmt.Errorf("ecs describe clusters: %w", err)
			}
			if len(described.Clusters) == 0 {
				// Listed but undescribed (eshu-hq/eshu#11280): ListClusters
				// named this ARN yet DescribeClusters described nothing
				// (failures carry MISSING and the clusters array stays
				// empty). Skipping silently commits green with zero ECS
				// facts and zero warnings, so the gap rides the warning
				// carrier instead. Children of an undescribed parent stay
				// unlisted: without a cluster record they cannot be
				// attributed, and attempting them burns API budget only to
				// risk replacing the warning with a hard error.
				undescribedClusters++
				if len(described.Failures) == 0 {
					undescribedReasons["no-failure-detail"]++
				}
				for _, failure := range described.Failures {
					reason := strings.TrimSpace(aws.ToString(failure.Reason))
					if reason == "" {
						reason = "unknown"
					}
					undescribedReasons[reason]++
				}
				continue
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
					listedServices += len(chunk)
					described, err := client.DescribeServices(ctx, ecsServiceDescribeInput(arn, chunk))
					if err != nil {
						return nil, fmt.Errorf("ecs describe services: %w", err)
					}
					if missing := len(chunk) - len(described.Services); missing > 0 {
						undescribedServices += missing
						tallyGapReasons(undescribedServiceReasons, described.Failures, missing)
					}
					for _, service := range described.Services {
						row, err := ecsServiceRecord(service, region)
						if err != nil {
							return nil, fmt.Errorf("ecs service record: %w", err)
						}
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
					listedTasks += len(chunk)
					described, err := client.DescribeTasks(ctx, &awsecs.DescribeTasksInput{Cluster: aws.String(arn), Tasks: chunk})
					if err != nil {
						return nil, fmt.Errorf("ecs describe tasks: %w", err)
					}
					if missing := len(chunk) - len(described.Tasks); missing > 0 {
						undescribedTasks += missing
						tallyGapReasons(undescribedTaskReasons, described.Failures, missing)
					}
					for _, task := range described.Tasks {
						row := ecsTaskRecord(task, region)
						if row.Resource == nil {
							return nil, fmt.Errorf("ecs described task has no ARN")
						}
						records = append(records, row)
						// Standalone tasks (run-task one-offs, Batch jobs)
						// pin revisions no service references; collect them
						// here so their definitions resolve like services'.
						records, err = collectECSTaskDefinition(ctx, client, records, aws.ToString(task.TaskDefinitionArn), region, seenDefinitions, key)
						if err != nil {
							return nil, err
						}
					}
				}
			}
		}
	}
	// Task definitions stay referenced-only: services and tasks collect the
	// revisions they pin inline above. Enumerating every registered revision
	// (thousands in a real account, including deregistered ones) throttles
	// DescribeTaskDefinition and fails the whole ECS leg with zero facts.
	return records, combineOptionalDenials(
		ecsDescribeGapDenial(region, listedClusters, undescribedClusters, undescribedReasons),
		ecsMemberGapDenial("DescribeServices", region, "services", "services-undescribed", "services_undescribed", listedServices, undescribedServices, undescribedServiceReasons),
		ecsMemberGapDenial("DescribeTasks", region, "tasks", "tasks-undescribed", "tasks_undescribed", listedTasks, undescribedTasks, undescribedTaskReasons),
	)
}

// tallyGapReasons folds one describe page's per-member failures into the
// aggregated reason shapes; members missing without a failure entry count
// as no-failure-detail, mirroring the cluster gap.
func tallyGapReasons(reasons map[string]int, failures []awsecstypes.Failure, missing int) {
	for _, failure := range failures {
		reason := strings.TrimSpace(aws.ToString(failure.Reason))
		if reason == "" {
			reason = "unknown"
		}
		reasons[reason]++
	}
	if remainder := missing - len(failures); remainder > 0 {
		reasons["no-failure-detail"] += remainder
	}
}

// ecsMemberGapDenial builds the warning carrier for service or task ARNs
// List named but the chunked describe could not describe
// (eshu-hq/eshu#11283). Counts and failure-reason shapes only, never the
// listed ARNs, so no account, ARN, or cluster identity reaches the
// operator surface. A nil return keeps the fully-described path
// warning-free.
func ecsMemberGapDenial(operation, region, unit, effect, kind string, listed, undescribed int, reasons map[string]int) *optionalReadDenied {
	if undescribed == 0 {
		return nil
	}
	summaries := make([]string, 0, len(reasons))
	for reason, count := range reasons {
		summaries = append(summaries, fmt.Sprintf("%sx%d", reason, count))
	}
	sort.Strings(summaries)
	summary := strings.Join(summaries, ",")
	if summary == "" {
		summary = "no-failure-detail"
	}
	return &optionalReadDenied{denials: []optionalDenial{{
		operation: operation,
		resource:  "region:" + region,
		effect:    effect,
		message: fmt.Sprintf("%s described %d of %d listed %s (%s)",
			operation, listed-undescribed, listed, unit, summary),
		attributes: map[string]any{
			"listed_" + unit:      listed,
			"undescribed_" + unit: undescribed,
			"reasons":             summary,
		},
		warningKind: kind,
		errorClass:  kind,
	}}}
}

// ecsDescribeGapDenial builds the warning carrier for clusters ListClusters
// named but DescribeClusters could not describe (eshu-hq/eshu#11280). The
// carrier holds counts and failure-reason shapes only, never the listed
// ARNs, so no account, ARN, or cluster identity reaches the operator
// surface. A nil return keeps the fully-described path warning-free.
func ecsDescribeGapDenial(region string, listed, undescribed int, reasons map[string]int) *optionalReadDenied {
	if undescribed == 0 {
		return nil
	}
	summaries := make([]string, 0, len(reasons))
	for reason, count := range reasons {
		summaries = append(summaries, fmt.Sprintf("%sx%d", reason, count))
	}
	sort.Strings(summaries)
	summary := strings.Join(summaries, ",")
	if summary == "" {
		summary = "no-failure-detail"
	}
	return &optionalReadDenied{denials: []optionalDenial{{
		operation: "DescribeClusters",
		resource:  "region:" + region,
		effect:    "clusters-undescribed",
		message: fmt.Sprintf("DescribeClusters described %d of %d listed cluster(s) (%s)",
			listed-undescribed, listed, summary),
		attributes: map[string]any{
			"listed_clusters":      listed,
			"undescribed_clusters": undescribed,
			"reasons":              summary,
		},
		warningKind: "clusters_undescribed",
		errorClass:  "clusters_undescribed",
	}}}
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
		return nil, fmt.Errorf("ecs describe task definition: %w", err)
	}
	if described == nil || described.TaskDefinition == nil {
		return nil, fmt.Errorf("ecs described task definition has no body")
	}
	row, err := ecsTaskDefinitionRecord(arn, *described.TaskDefinition, described.Tags, region, key)
	if err != nil {
		return nil, fmt.Errorf("ecs task definition record: %w", err)
	}
	if row.Resource == nil {
		return nil, fmt.Errorf("ecs described task definition has no matching ARN")
	}
	seen[arn] = struct{}{}
	return append(records, row), nil
}
