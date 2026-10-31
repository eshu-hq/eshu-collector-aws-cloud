// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// ssmParameterUsesKMSKeyRelationshipType is the in-tree catalog relationship
// for an SSM SecureString parameter's KMS dependency. The pinned factschema
// release exposes no constant for it yet, so the literal below mirrors the
// volume-KMS precedent; the parity test locks the value against the in-tree
// oracle key.
const ssmParameterUsesKMSKeyRelationshipType = "ssm_parameter_uses_kms_key"

// ssmParameterRecord maps one DescribeParameters row plus its tag list into
// the typed parameter resource plus its parameter-to-KMS edge, mirroring the
// in-tree ssm scanner's parameter observation field for field. Only
// source-reported metadata enters the fact: raw descriptions and allowed
// patterns reduce to presence booleans, policy entries keep type and status
// only (policy JSON never enters), and parameter values are never read. It
// adds no AWS API call beyond the tag list the caller supplies.
func ssmParameterRecord(parameter ssmtypes.ParameterMetadata, tagList []ssmtypes.Tag, region string) (collector.Record, error) {
	arn := strings.TrimSpace(aws.ToString(parameter.ARN))
	name := strings.TrimSpace(aws.ToString(parameter.Name))
	if arn == "" && name == "" {
		return collector.Record{}, fmt.Errorf("ssm parameter has no source identity")
	}
	resourceID := arn
	if resourceID == "" {
		resourceID = name
	}
	result := record(arn, "ssm", region, name, "parameter")
	result.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "ssm",
		ResourceType: awsv1.ResourceTypeSSMParameter,
		ResourceID:   resourceID, ARN: arn, Name: name,
		Tags:               ssmParameterTags(tagList),
		SourceRecordID:     resourceID,
		CorrelationAnchors: []string{arn, name},
		Attributes: map[string]any{
			"type":                    strings.TrimSpace(string(parameter.Type)),
			"tier":                    strings.TrimSpace(string(parameter.Tier)),
			"data_type":               strings.TrimSpace(aws.ToString(parameter.DataType)),
			"key_id":                  strings.TrimSpace(aws.ToString(parameter.KeyId)),
			"last_modified_at":        ssmParameterTime(parameter.LastModifiedDate),
			"description_present":     strings.TrimSpace(aws.ToString(parameter.Description)) != "",
			"allowed_pattern_present": strings.TrimSpace(aws.ToString(parameter.AllowedPattern)) != "",
			"policies":                ssmParameterPolicies(parameter.Policies),
		},
	}
	if keyID := strings.TrimSpace(aws.ToString(parameter.KeyId)); keyID != "" {
		keyARN := ""
		if strings.HasPrefix(keyID, "arn:") {
			keyARN = keyID
		}
		result.Relationship = &collector.LiveRelationship{
			Region: region, ServiceKind: "ssm", RelationshipType: ssmParameterUsesKMSKeyRelationshipType,
			SourceResourceID: resourceID, SourceARN: arn,
			TargetResourceID: keyID, TargetARN: keyARN, TargetType: "aws_kms_key",
			SourceRecordID: resourceID + "->" + ssmParameterUsesKMSKeyRelationshipType + ":" + keyID,
		}
	}
	return result, nil
}

// listSSMParameterTags reads the tag list for one parameter name, mirroring
// the in-tree awssdk client's per-parameter ListTagsForResource pass. A blank
// name carries no addressable resource and returns nil without a call.
func listSSMParameterTags(ctx context.Context, client *awsssm.Client, name string) ([]ssmtypes.Tag, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil
	}
	output, err := client.ListTagsForResource(ctx, &awsssm.ListTagsForResourceInput{
		ResourceId:   aws.String(name),
		ResourceType: ssmtypes.ResourceTypeForTaggingParameter,
	})
	if err != nil {
		return nil, fmt.Errorf("ssm list tags for parameter %q: %w", name, err)
	}
	if output == nil {
		return nil, nil
	}
	return output.TagList, nil
}

// ssmParameterTags mirrors the in-tree mapper's tag shape: keys trim,
// blank keys drop, values pass through untouched, and an empty list stays
// nil (not an empty map).
func ssmParameterTags(input []ssmtypes.Tag) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for _, tag := range input {
		key := strings.TrimSpace(aws.ToString(tag.Key))
		if key == "" {
			continue
		}
		output[key] = aws.ToString(tag.Value)
	}
	if len(output) == 0 {
		return nil
	}
	return output
}

// ssmParameterPolicies mirrors the in-tree mapper's policy shape: each entry
// keeps type and status only, all-blank entries drop, and an empty list stays
// nil. Policy JSON text never enters a fact.
func ssmParameterPolicies(input []ssmtypes.ParameterInlinePolicy) []map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make([]map[string]string, 0, len(input))
	for _, policy := range input {
		entry := map[string]string{
			"type":   strings.TrimSpace(aws.ToString(policy.PolicyType)),
			"status": strings.TrimSpace(aws.ToString(policy.PolicyStatus)),
		}
		if entry["type"] == "" && entry["status"] == "" {
			continue
		}
		output = append(output, entry)
	}
	if len(output) == 0 {
		return nil
	}
	return output
}

// ssmParameterTime mirrors the in-tree time shape: an absent timestamp stays
// nil (not the zero time) and a present one normalizes to UTC.
func ssmParameterTime(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return value.UTC()
}
