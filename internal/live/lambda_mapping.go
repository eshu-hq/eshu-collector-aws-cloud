// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// lambdaEventSourceMappingResourceType is the in-tree catalog type for a
// Lambda event source mapping. The pinned factschema release exposes no
// constant for it yet, so the literal below mirrors the alias precedent;
// the parity test locks the value against the in-tree oracle key.
const lambdaEventSourceMappingResourceType = "aws_lambda_event_source_mapping"

// lambdaEventSourceMappingRecord maps one ListEventSourceMappings row into
// the typed mapping resource plus its mapping-to-function edge, mirroring
// the in-tree lambda scanner's mapping observation field for field. Only
// source-reported routing and delivery metadata enters the fact; the polled
// event payload is never read. It adds no AWS API call.
func lambdaEventSourceMappingRecord(mapping lambdatypes.EventSourceMappingConfiguration, functionARN, region string) (collector.Record, error) {
	mappingARN := strings.TrimSpace(aws.ToString(mapping.EventSourceMappingArn))
	uuid := strings.TrimSpace(aws.ToString(mapping.UUID))
	mappingID := mappingARN
	if mappingID == "" {
		mappingID = uuid
	}
	if mappingID == "" {
		return collector.Record{}, fmt.Errorf("lambda event source mapping has no source identity")
	}
	targetARN := strings.TrimSpace(aws.ToString(mapping.FunctionArn))
	if targetARN == "" {
		targetARN = strings.TrimSpace(functionARN)
	}
	eventSourceARN := strings.TrimSpace(aws.ToString(mapping.EventSourceArn))
	state := strings.TrimSpace(aws.ToString(mapping.State))
	result := record(mappingARN, "lambda", region, uuid, "event-source-mapping")
	result.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "lambda", ResourceType: lambdaEventSourceMappingResourceType,
		ResourceID: mappingID, ARN: mappingARN, Name: uuid, State: state, SourceRecordID: mappingID,
		CorrelationAnchors: []string{mappingID, eventSourceARN, targetARN},
		Attributes: map[string]any{
			"batch_size":             aws.ToInt32(mapping.BatchSize),
			"event_source_arn":       eventSourceARN,
			"function_arn":           targetARN,
			"last_processing_result": strings.TrimSpace(aws.ToString(mapping.LastProcessingResult)),
			"maximum_retry_attempts": aws.ToInt32(mapping.MaximumRetryAttempts),
			"parallelization_factor": aws.ToInt32(mapping.ParallelizationFactor),
			"starting_position":      strings.TrimSpace(string(mapping.StartingPosition)),
			"uuid":                   uuid,
		},
	}
	if targetARN != "" {
		result.Relationship = &collector.LiveRelationship{
			Region: region, ServiceKind: "lambda", RelationshipType: "lambda_event_source_mapping_targets_function",
			SourceResourceID: mappingID, SourceARN: mappingARN,
			TargetResourceID: targetARN, TargetARN: targetARN, TargetType: awsv1.ResourceTypeLambdaFunction,
			SourceRecordID: mappingID + "#function#" + targetARN,
			Attributes: map[string]any{
				"event_source_arn": eventSourceARN,
				"state":            state,
				"uuid":             uuid,
			},
		}
	}
	return result, nil
}
