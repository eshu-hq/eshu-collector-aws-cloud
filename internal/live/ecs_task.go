// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// ecsTaskRecord carries reported DescribeTasks metadata into a typed resource.
func ecsTaskRecord(task awsecstypes.Task, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(task.TaskArn))
	row := record(arn, "ecs", region, lastSegment(arn, "/"), "task")
	if arn == "" {
		return row
	}
	definitionARN := strings.TrimSpace(aws.ToString(task.TaskDefinitionArn))
	interfaces, interfaceIDs := ecsTaskNetworkInterfaces(task.Attachments)
	var startedAt any
	if task.StartedAt != nil && !task.StartedAt.IsZero() {
		startedAt = task.StartedAt.UTC()
	}
	row.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "ecs", ResourceType: "aws_ecs_task",
		ResourceID: arn, ARN: arn, Name: arn, State: aws.ToString(task.LastStatus),
		Attributes: map[string]any{
			"cluster_arn":         strings.TrimSpace(aws.ToString(task.ClusterArn)),
			"containers":          ecsTaskContainers(task.Containers),
			"desired_status":      strings.TrimSpace(aws.ToString(task.DesiredStatus)),
			"group":               strings.TrimSpace(aws.ToString(task.Group)),
			"launch_type":         strings.TrimSpace(string(task.LaunchType)),
			"network_interfaces":  interfaces,
			"started_at":          startedAt,
			"task_definition_arn": definitionARN,
		},
		CorrelationAnchors: append([]string{arn, definitionARN}, interfaceIDs...), SourceRecordID: arn,
	}
	row.Relationships = ecsTaskNetworkInterfaceRelationships(arn, region, interfaces, interfaceIDs)
	return row
}

func ecsTaskContainers(containers []awsecstypes.Container) []map[string]string {
	if len(containers) == 0 {
		return nil
	}
	mapped := make([]map[string]string, 0, len(containers))
	for _, container := range containers {
		mapped = append(mapped, map[string]string{
			"image":        strings.TrimSpace(aws.ToString(container.Image)),
			"image_digest": strings.TrimSpace(aws.ToString(container.ImageDigest)),
			"name":         strings.TrimSpace(aws.ToString(container.Name)),
			"runtime_id":   strings.TrimSpace(aws.ToString(container.RuntimeId)),
		})
	}
	return mapped
}

func ecsTaskNetworkInterfaces(attachments []awsecstypes.Attachment) ([]map[string]any, []string) {
	var mapped []map[string]any
	var ids []string
	for _, attachment := range attachments {
		if strings.TrimSpace(aws.ToString(attachment.Type)) != "ElasticNetworkInterface" {
			continue
		}
		details := map[string]string{}
		for _, detail := range attachment.Details {
			key := strings.TrimSpace(aws.ToString(detail.Name))
			if _, seen := details[key]; !seen {
				details[key] = aws.ToString(detail.Value)
			}
		}
		id := strings.TrimSpace(details["networkInterfaceId"])
		if id == "" {
			continue
		}
		mapped = append(mapped, map[string]any{
			"mac_address":          strings.TrimSpace(details["macAddress"]),
			"network_interface_id": id,
			"private_ipv4_address": strings.TrimSpace(details["privateIPv4Address"]),
			"subnet_id":            strings.TrimSpace(details["subnetId"]),
		})
		ids = append(ids, id)
	}
	return mapped, ids
}
