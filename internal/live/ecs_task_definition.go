// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	awsecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-sdk/collector/marker"
)

// ecsTaskDefinitionDescribeInput requests the tags in the legacy observation.
func ecsTaskDefinitionDescribeInput(arn string) *awsecs.DescribeTaskDefinitionInput {
	return &awsecs.DescribeTaskDefinitionInput{
		TaskDefinition: aws.String(arn),
		Include:        []awsecstypes.TaskDefinitionField{awsecstypes.TaskDefinitionFieldTags},
	}
}

// ecsTaskDefinitionRecord carries reported task-definition metadata. Container
// environment values are keyed markers; secret references remain metadata.
func ecsTaskDefinitionRecord(listedARN string, definition awsecstypes.TaskDefinition, tags []awsecstypes.Tag, region string, key marker.Key) collector.Record {
	listedARN = strings.TrimSpace(listedARN)
	arn := strings.TrimSpace(aws.ToString(definition.TaskDefinitionArn))
	row := record(listedARN, "ecs", region, lastSegment(listedARN, "/"), "task-definition")
	if arn == "" || arn != listedARN {
		return row
	}
	family := strings.TrimSpace(aws.ToString(definition.Family))
	var registeredAt any
	if definition.RegisteredAt != nil && !definition.RegisteredAt.IsZero() {
		registeredAt = definition.RegisteredAt.UTC()
	}
	compatibilities := ecsTaskDefinitionCompatibilities(definition.RequiresCompatibilities)
	row.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "ecs", ResourceType: "aws_ecs_task_definition",
		ResourceID: arn, ARN: arn, Name: family, State: string(definition.Status), Tags: ecsClusterTags(tags),
		Attributes: map[string]any{
			"containers":               ecsContainerDefinitions(definition.ContainerDefinitions, key),
			"cpu":                      strings.TrimSpace(aws.ToString(definition.Cpu)),
			"execution_role_arn":       strings.TrimSpace(aws.ToString(definition.ExecutionRoleArn)),
			"memory":                   strings.TrimSpace(aws.ToString(definition.Memory)),
			"network_mode":             strings.TrimSpace(string(definition.NetworkMode)),
			"registered_at":            registeredAt,
			"requires_compatibilities": compatibilities,
			"revision":                 definition.Revision,
			"task_role_arn":            strings.TrimSpace(aws.ToString(definition.TaskRoleArn)),
		},
		CorrelationAnchors: []string{arn, family, family + ":" + strconv.Itoa(int(definition.Revision))},
		SourceRecordID:     arn,
	}
	return row
}

func ecsTaskDefinitionCompatibilities(values []awsecstypes.Compatibility) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, string(value))
	}
	return result
}

func ecsContainerDefinitions(containers []awsecstypes.ContainerDefinition, key marker.Key) []map[string]any {
	if len(containers) == 0 {
		return nil
	}
	result := make([]map[string]any, 0, len(containers))
	for _, container := range containers {
		var environment []map[string]any
		for _, variable := range container.Environment {
			name := strings.TrimSpace(aws.ToString(variable.Name))
			environment = append(environment, map[string]any{
				"name":  name,
				"value": redactAWSString(aws.ToString(variable.Value), "ecs.task_definition.container.environment."+name, key),
			})
		}
		var secrets []map[string]string
		for _, secret := range container.Secrets {
			secrets = append(secrets, map[string]string{
				"name":       strings.TrimSpace(aws.ToString(secret.Name)),
				"value_from": strings.TrimSpace(aws.ToString(secret.ValueFrom)),
			})
		}
		result = append(result, map[string]any{
			"environment": environment,
			"essential":   aws.ToBool(container.Essential),
			"image":       strings.TrimSpace(aws.ToString(container.Image)),
			"name":        strings.TrimSpace(aws.ToString(container.Name)),
			"secrets":     secrets,
		})
	}
	return result
}
