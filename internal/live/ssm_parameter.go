// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// ssmParameterRecord retains only metadata returned by DescribeParameters.
// It never copies values, descriptions, allowed patterns, or policy JSON.
func ssmParameterRecord(raw ssmtypes.ParameterMetadata, region string) (collector.Record, error) {
	arn := strings.TrimSpace(aws.ToString(raw.ARN))
	name := strings.TrimSpace(aws.ToString(raw.Name))
	id := arn
	if id == "" {
		id = name
	}
	if id == "" {
		return collector.Record{}, fmt.Errorf("ssm parameter requires ARN or name")
	}
	row := record(arn, "ssm", region, name, "parameter")
	row.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "ssm", ResourceType: "aws_ssm_parameter",
		ResourceID: id, ARN: arn, Name: name, SourceRecordID: id,
		CorrelationAnchors: []string{arn, name},
		Attributes: map[string]any{
			"type":                    strings.TrimSpace(string(raw.Type)),
			"tier":                    strings.TrimSpace(string(raw.Tier)),
			"data_type":               strings.TrimSpace(aws.ToString(raw.DataType)),
			"key_id":                  strings.TrimSpace(aws.ToString(raw.KeyId)),
			"last_modified_at":        ssmParameterTime(raw.LastModifiedDate),
			"description_present":     strings.TrimSpace(aws.ToString(raw.Description)) != "",
			"allowed_pattern_present": strings.TrimSpace(aws.ToString(raw.AllowedPattern)) != "",
			"policies":                ssmParameterPolicies(raw.Policies),
		},
	}
	if keyID := strings.TrimSpace(aws.ToString(raw.KeyId)); keyID != "" {
		targetARN := ""
		if strings.HasPrefix(keyID, "arn:") {
			targetARN = keyID
		}
		row.Relationship = &collector.LiveRelationship{
			Region: region, ServiceKind: "ssm", RelationshipType: "ssm_parameter_uses_kms_key",
			SourceResourceID: id, SourceARN: arn, TargetResourceID: keyID, TargetARN: targetARN,
			TargetType: "aws_kms_key", SourceRecordID: id + "->ssm_parameter_uses_kms_key:" + keyID,
		}
	}
	return row, nil
}

func ssmParameterTime(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return value.UTC()
}

func ssmParameterPolicies(input []ssmtypes.ParameterInlinePolicy) []map[string]string {
	if len(input) == 0 {
		return nil
	}
	var output []map[string]string
	for _, policy := range input {
		typ := strings.TrimSpace(aws.ToString(policy.PolicyType))
		status := strings.TrimSpace(aws.ToString(policy.PolicyStatus))
		if typ == "" && status == "" {
			continue
		}
		output = append(output, map[string]string{"type": typ, "status": status})
	}
	return output
}
