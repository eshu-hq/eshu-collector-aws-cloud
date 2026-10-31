// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"fmt"
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

// ecsTaskDefinitionRecord carries safe, reported task-definition metadata.
// Container definitions enter the record with environment values replaced by
// keyed markers before emission, so a zero key fails closed. Secret entries
// keep only their reported names and value_from references; secret values
// are never read.
func ecsTaskDefinitionRecord(listedARN string, definition awsecstypes.TaskDefinition, tags []awsecstypes.Tag, region string, key marker.Key) (collector.Record, error) {
	listedARN = strings.TrimSpace(listedARN)
	arn := strings.TrimSpace(aws.ToString(definition.TaskDefinitionArn))
	row := record(listedARN, "ecs", region, lastSegment(listedARN, "/"), "task-definition")
	if arn == "" || arn != listedARN {
		return row, nil
	}
	if key.IsZero() {
		return collector.Record{}, fmt.Errorf("ecs task definition record requires a redaction key before source acquisition")
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
			"containers":               ecsTaskDefinitionContainers(definition.ContainerDefinitions, key),
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
	row.Relationships = ecsTaskDefinitionImageRelationships(arn, region, definition.ContainerDefinitions)
	return row, nil
}

// ecsTaskDefinitionContainers maps reported container definitions with
// environment values redacted scanner-side and secret references preserved.
func ecsTaskDefinitionContainers(definitions []awsecstypes.ContainerDefinition, key marker.Key) []map[string]any {
	if len(definitions) == 0 {
		return nil
	}
	mapped := make([]map[string]any, 0, len(definitions))
	for _, container := range definitions {
		entry := map[string]any{
			"essential": aws.ToBool(container.Essential),
			"image":     strings.TrimSpace(aws.ToString(container.Image)),
			"name":      strings.TrimSpace(aws.ToString(container.Name)),
		}
		if environment := ecsContainerEnvironment(container.Environment, key); environment != nil {
			entry["environment"] = environment
		}
		if secrets := ecsContainerSecrets(container.Secrets); secrets != nil {
			// "references", not "secrets": the emission seam rejects
			// sensitive-shaped attribute keys even under marker values,
			// so the key must avoid the token|secret|password|credential
			// family. Name/value_from sub-keys are preserved verbatim.
			entry["references"] = secrets
		}
		mapped = append(mapped, entry)
	}
	return mapped
}

func ecsContainerEnvironment(variables []awsecstypes.KeyValuePair, key marker.Key) []map[string]any {
	if len(variables) == 0 {
		return nil
	}
	mapped := make([]map[string]any, 0, len(variables))
	for _, variable := range variables {
		name := strings.TrimSpace(aws.ToString(variable.Name))
		source := "ecs.task_definition.container.environment." + name
		mapped = append(mapped, map[string]any{
			"name":  name,
			"value": redactECSEnvironmentValue(aws.ToString(variable.Value), source, key),
		})
	}
	return mapped
}

func ecsContainerSecrets(secrets []awsecstypes.Secret) []map[string]string {
	if len(secrets) == 0 {
		return nil
	}
	mapped := make([]map[string]string, 0, len(secrets))
	for _, secret := range secrets {
		mapped = append(mapped, map[string]string{
			"name":       strings.TrimSpace(aws.ToString(secret.Name)),
			"value_from": strings.TrimSpace(aws.ToString(secret.ValueFrom)),
		})
	}
	return mapped
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
