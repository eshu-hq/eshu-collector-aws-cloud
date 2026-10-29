// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
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
