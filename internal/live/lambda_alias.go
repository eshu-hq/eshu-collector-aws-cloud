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

// lambdaAliasRecord retains source-reported alias identity and routing, while
// excluding the user-authored description from shared facts.
func lambdaAliasRecord(functionARN string, alias lambdatypes.AliasConfiguration, region string) (collector.Record, error) {
	functionARN = strings.TrimSpace(functionARN)
	aliasARN := strings.TrimSpace(aws.ToString(alias.AliasArn))
	name := strings.TrimSpace(aws.ToString(alias.Name))
	if aliasARN != "" && functionARN != "" && !strings.HasPrefix(aliasARN, functionARN+":") {
		return collector.Record{}, fmt.Errorf("Lambda alias identity differs from parent function")
	}
	resourceID := aliasARN
	if resourceID == "" && functionARN != "" && name != "" {
		resourceID = functionARN + ":" + name
	}
	if resourceID == "" {
		return collector.Record{}, fmt.Errorf("Lambda alias has no source identity")
	}
	weights := map[string]float64(nil)
	if alias.RoutingConfig != nil && len(alias.RoutingConfig.AdditionalVersionWeights) != 0 {
		weights = make(map[string]float64, len(alias.RoutingConfig.AdditionalVersionWeights))
		for version, weight := range alias.RoutingConfig.AdditionalVersionWeights {
			weights[version] = weight
		}
	}
	version := strings.TrimSpace(aws.ToString(alias.FunctionVersion))
	result := record(aliasARN, "lambda", region, name, "alias")
	result.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "lambda", ResourceType: "aws_lambda_alias",
		ResourceID: resourceID, ARN: aliasARN, Name: name, SourceRecordID: resourceID,
		CorrelationAnchors: []string{aliasARN, name, functionARN},
		Attributes: map[string]any{
			"function_arn": functionARN, "function_version": version,
			"revision_id": strings.TrimSpace(aws.ToString(alias.RevisionId)), "routing_weights": weights,
		},
	}
	if aliasARN != "" && functionARN != "" {
		result.Relationship = &collector.LiveRelationship{
			Region: region, ServiceKind: "lambda", RelationshipType: "lambda_alias_targets_function",
			SourceResourceID: aliasARN, SourceARN: aliasARN,
			TargetResourceID: functionARN, TargetARN: functionARN, TargetType: awsv1.ResourceTypeLambdaFunction,
			SourceRecordID: aliasARN + "#function#" + functionARN,
			Attributes:     map[string]any{"function_version": version, "routing_weights": weights},
		}
	}
	return result, nil
}
