// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

func TestLambdaFunctionRecordCarriesListFunctionsMetadata(t *testing.T) {
	function := lambdatypes.FunctionConfiguration{
		FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:worker"),
		FunctionName: aws.String("worker"),
		State:        lambdatypes.StateActive,
		Runtime:      lambdatypes.RuntimeNodejs20x,
		Role:         aws.String("arn:aws:iam::123456789012:role/worker"),
		Environment:  &lambdatypes.EnvironmentResponse{Variables: map[string]string{"API_KEY": "sensitive-value"}},
	}
	got, err := lambdaFunctionRecord(function, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Resource == nil || got.Resource.ResourceID != *function.FunctionArn || got.Resource.Name != "worker" || got.Resource.State != "Active" {
		t.Fatalf("function identity = %+v", got.Resource)
	}
	if got.Resource.Attributes["role_arn"] != *function.Role || got.Resource.Attributes["runtime"] != string(function.Runtime) {
		t.Fatalf("function attributes = %#v", got.Resource.Attributes)
	}
	if _, ok := got.Resource.Attributes["environment"]; ok {
		t.Fatal("unredacted environment values cannot enter the typed fact")
	}
	if _, ok := got.Resource.Attributes["resolved_image_uri"]; ok {
		t.Fatal("ListFunctions does not establish resolved image evidence")
	}
	if len(got.Resource.Tags) != 0 {
		t.Fatalf("ListFunctions does not return function tags: %#v", got.Resource.Tags)
	}
	if got.Name != "worker" || got.ID != *function.FunctionArn {
		t.Fatalf("transitional record = %+v", got)
	}
}

func TestLambdaGetFunctionRecordRejectsMismatchedIdentityAndUnsafeReferences(t *testing.T) {
	listed := lambdatypes.FunctionConfiguration{FunctionArn: aws.String("arn:aws:lambda:us-east-1:123456789012:function:worker")}
	for _, test := range []struct {
		name   string
		output *awslambda.GetFunctionOutput
	}{
		{name: "missing response"},
		{name: "different function", output: &awslambda.GetFunctionOutput{Configuration: &lambdatypes.FunctionConfiguration{FunctionArn: aws.String("arn:aws:lambda:us-east-1:123456789012:function:other")}}},
		{name: "URL in image field", output: &awslambda.GetFunctionOutput{Code: &lambdatypes.FunctionCodeLocation{ImageUri: aws.String("https://user:secret@example.com/image")}}},
		{name: "query in image field", output: &awslambda.GetFunctionOutput{Code: &lambdatypes.FunctionCodeLocation{ImageUri: aws.String("123456789012.dkr.ecr.us-east-1.amazonaws.com/team/worker:prod?token=secret")}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := lambdaGetFunctionRecord(listed, test.output, "us-east-1")
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe GetFunction output error = %v", err)
			}
		})
	}
}

func TestLambdaFunctionRecordCarriesVPCAndLoggingConfiguration(t *testing.T) {
	function := lambdatypes.FunctionConfiguration{
		FunctionName:  aws.String("worker"),
		Architectures: []lambdatypes.Architecture{" arm64 ", "", "  "},
		VpcConfig: &lambdatypes.VpcConfigResponse{
			VpcId: aws.String("vpc-1"), SubnetIds: []string{"subnet-1"},
			SecurityGroupIds: []string{"sg-1"}, Ipv6AllowedForDualStack: aws.Bool(true),
		},
		LoggingConfig: &lambdatypes.LoggingConfig{
			LogGroup:            aws.String("/aws/lambda/worker"),
			LogFormat:           lambdatypes.LogFormatJson,
			ApplicationLogLevel: lambdatypes.ApplicationLogLevelInfo,
			SystemLogLevel:      lambdatypes.SystemLogLevelWarn,
		},
	}
	got, err := lambdaFunctionRecord(function, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	attributes := got.Resource.Attributes
	if want := []string{"arm64"}; !reflect.DeepEqual(attributes["architectures"], want) {
		t.Fatalf("architectures = %#v, want %#v", attributes["architectures"], want)
	}
	if want := map[string]any{"vpc_id": "vpc-1", "subnet_ids": []string{"subnet-1"}, "security_group_ids": []string{"sg-1"}, "ipv6_allowed_for_dual_stack": true}; !reflect.DeepEqual(attributes["vpc_config"], want) {
		t.Fatalf("vpc_config = %#v, want %#v", attributes["vpc_config"], want)
	}
	if want := map[string]any{"log_group": "/aws/lambda/worker", "log_format": "JSON", "application_log_level": "INFO", "system_log_level": "WARN"}; !reflect.DeepEqual(attributes["logging_config"], want) {
		t.Fatalf("logging_config = %#v, want %#v", attributes["logging_config"], want)
	}
}

func TestLambdaFunctionRecordOmitsAbsentVPCAndLoggingConfiguration(t *testing.T) {
	got, err := lambdaFunctionRecord(lambdatypes.FunctionConfiguration{FunctionName: aws.String("worker")}, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"vpc_config", "logging_config"} {
		if value, present := got.Resource.Attributes[key]; present && !reflect.DeepEqual(value, map[string]any(nil)) {
			t.Fatalf("%s = %#v, want absent or nil", key, value)
		}
	}
}
