// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// lambdaFunctionRecord retains only fields supplied by ListFunctions. Tags,
// environment values, code download URLs, and resolved image evidence require
// separate reads or keyed redaction before they can be emitted.
func lambdaFunctionRecord(function lambdatypes.FunctionConfiguration, region string) (collector.Record, error) {
	arn := strings.TrimSpace(aws.ToString(function.FunctionArn))
	name := strings.TrimSpace(aws.ToString(function.FunctionName))
	if arn == "" && name == "" {
		return collector.Record{}, fmt.Errorf("Lambda function has no source identity")
	}
	result := record(arn, "lambda", region, name, "function")
	resourceID := arn
	if resourceID == "" {
		resourceID = name
	}
	result.Resource = &collector.LiveResource{
		Region:             region,
		ServiceKind:        "lambda",
		ResourceType:       awsv1.ResourceTypeLambdaFunction,
		ResourceID:         resourceID,
		ARN:                arn,
		Name:               name,
		State:              strings.TrimSpace(string(function.State)),
		SourceRecordID:     resourceID,
		CorrelationAnchors: []string{arn, name},
		Attributes: map[string]any{
			"architectures":      lambdaArchitectures(function.Architectures),
			"code_sha256":        strings.TrimSpace(aws.ToString(function.CodeSha256)),
			"code_size":          function.CodeSize,
			"description":        strings.TrimSpace(aws.ToString(function.Description)),
			"handler":            strings.TrimSpace(aws.ToString(function.Handler)),
			"kms_key_arn":        strings.TrimSpace(aws.ToString(function.KMSKeyArn)),
			"last_modified":      lambdaLastModified(aws.ToString(function.LastModified)),
			"last_update_status": strings.TrimSpace(string(function.LastUpdateStatus)),
			"logging_config":     lambdaLoggingConfig(function.LoggingConfig),
			"memory_size":        aws.ToInt32(function.MemorySize),
			"package_type":       strings.TrimSpace(string(function.PackageType)),
			"role_arn":           strings.TrimSpace(aws.ToString(function.Role)),
			"runtime":            strings.TrimSpace(string(function.Runtime)),
			"timeout_seconds":    aws.ToInt32(function.Timeout),
			"version":            strings.TrimSpace(aws.ToString(function.Version)),
			"vpc_config":         lambdaVPCConfig(function.VpcConfig),
		},
	}
	return result, nil
}

func lambdaArchitectures(values []lambdatypes.Architecture) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if architecture := strings.TrimSpace(string(value)); architecture != "" {
			result = append(result, architecture)
		}
	}
	return result
}

func lambdaVPCConfig(config *lambdatypes.VpcConfigResponse) map[string]any {
	if config == nil || (aws.ToString(config.VpcId) == "" && len(config.SubnetIds) == 0 && len(config.SecurityGroupIds) == 0) {
		return nil
	}
	return map[string]any{
		"ipv6_allowed_for_dual_stack": aws.ToBool(config.Ipv6AllowedForDualStack),
		"security_group_ids":          append([]string(nil), config.SecurityGroupIds...),
		"subnet_ids":                  append([]string(nil), config.SubnetIds...),
		"vpc_id":                      strings.TrimSpace(aws.ToString(config.VpcId)),
	}
}

func lambdaLoggingConfig(config *lambdatypes.LoggingConfig) map[string]any {
	if config == nil || (aws.ToString(config.LogGroup) == "" && config.LogFormat == "" && config.ApplicationLogLevel == "" && config.SystemLogLevel == "") {
		return nil
	}
	return map[string]any{
		"application_log_level": strings.TrimSpace(string(config.ApplicationLogLevel)),
		"log_format":            strings.TrimSpace(string(config.LogFormat)),
		"log_group":             strings.TrimSpace(aws.ToString(config.LogGroup)),
		"system_log_level":      strings.TrimSpace(string(config.SystemLogLevel)),
	}
}

func lambdaLastModified(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000-0700", time.RFC3339} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC()
		}
	}
	return nil
}
