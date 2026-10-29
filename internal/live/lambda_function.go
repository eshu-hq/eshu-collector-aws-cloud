// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// lambdaFunctionRecord retains safe configuration fields. Environment values
// require a keyed redaction path and never enter this record.
func lambdaFunctionRecord(function lambdatypes.FunctionConfiguration, region string) (collector.Record, error) {
	arn := strings.TrimSpace(aws.ToString(function.FunctionArn))
	name := strings.TrimSpace(aws.ToString(function.FunctionName))
	if arn == "" && name == "" {
		return collector.Record{}, fmt.Errorf("lambda function has no source identity")
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

var lambdaECRImageReference = regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?/[A-Za-z0-9._/-]+(?::[A-Za-z0-9._-]+|@sha256:[a-fA-F0-9]{64})$`)

// lambdaGetFunctionRecord maps the authoritative GetFunction configuration and
// stable code references without copying package URLs, environment, or tags.
func lambdaGetFunctionRecord(listed lambdatypes.FunctionConfiguration, output *awslambda.GetFunctionOutput, region string) (collector.Record, error) {
	if output == nil {
		return collector.Record{}, fmt.Errorf("lambda GetFunction returned no response")
	}
	configuration := listed
	if output.Configuration != nil {
		configuration = *output.Configuration
	}
	listedID := strings.TrimSpace(aws.ToString(listed.FunctionArn))
	if listedID == "" {
		listedID = strings.TrimSpace(aws.ToString(listed.FunctionName))
	}
	actualID := strings.TrimSpace(aws.ToString(configuration.FunctionArn))
	if actualID == "" {
		actualID = strings.TrimSpace(aws.ToString(configuration.FunctionName))
	}
	if listedID != actualID {
		return collector.Record{}, fmt.Errorf("lambda GetFunction identity differs from ListFunctions")
	}
	listedName := strings.TrimSpace(aws.ToString(listed.FunctionName))
	actualName := strings.TrimSpace(aws.ToString(configuration.FunctionName))
	if listedName != "" && actualName != "" && listedName != actualName {
		return collector.Record{}, fmt.Errorf("lambda GetFunction name differs from ListFunctions")
	}
	result, err := lambdaFunctionRecord(configuration, region)
	if err != nil {
		return collector.Record{}, err
	}
	if output.Code == nil {
		return result, nil
	}
	for _, reference := range []struct{ key, value string }{
		{key: "image_uri", value: aws.ToString(output.Code.ImageUri)},
		{key: "resolved_image_uri", value: aws.ToString(output.Code.ResolvedImageUri)},
	} {
		key, value := reference.key, reference.value
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !lambdaECRImageReference.MatchString(value) {
			return collector.Record{}, fmt.Errorf("lambda GetFunction returned unsafe image reference")
		}
		result.Resource.Attributes[key] = value
		result.Resource.CorrelationAnchors = append(result.Resource.CorrelationAnchors, value)
	}
	if imageURI, ok := result.Resource.Attributes["image_uri"].(string); ok && result.Resource.ARN != "" {
		resolved, ok := result.Resource.Attributes["resolved_image_uri"].(string)
		if !ok {
			resolved = ""
		}
		arn := result.Resource.ARN
		result.Relationship = &collector.LiveRelationship{
			Region: region, ServiceKind: "lambda", RelationshipType: "lambda_function_uses_image",
			SourceResourceID: arn, SourceARN: arn, TargetResourceID: imageURI,
			TargetType: "container_image", SourceRecordID: arn + "#container-image#" + imageURI,
			Attributes: map[string]any{
				"package_type":       strings.TrimSpace(string(configuration.PackageType)),
				"resolved_image_uri": resolved,
			},
		}
	}
	if keyARN := strings.TrimSpace(aws.ToString(output.Code.SourceKMSKeyArn)); keyARN != "" {
		parsed, err := awsarn.Parse(keyARN)
		if err != nil || parsed.Service != "kms" || parsed.Partition != partitionForRegion(region) ||
			parsed.Region != region || !regionPattern.MatchString(parsed.Region) ||
			!accountPattern.MatchString(parsed.AccountID) || !lambdaKMSKeyResource.MatchString(parsed.Resource) {
			return collector.Record{}, fmt.Errorf("lambda GetFunction returned unsafe source KMS key ARN")
		}
		result.Resource.Attributes["source_kms_key_arn"] = keyARN
	}
	return result, nil
}

var lambdaKMSKeyResource = regexp.MustCompile(`^key/[A-Za-z0-9-]+$`)

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
