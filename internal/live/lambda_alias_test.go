// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

func TestLambdaAliasRecordPreservesReportedRouting(t *testing.T) {
	const functionARN = "arn:aws:lambda:us-east-1:123456789012:function:worker"
	const aliasARN = functionARN + ":live"
	alias := lambdatypes.AliasConfiguration{
		AliasArn: aws.String(aliasARN), Name: aws.String("live"),
		FunctionVersion: aws.String("12"), RevisionId: aws.String("rev-1"),
		Description:   aws.String("user text that must not be emitted"),
		RoutingConfig: &lambdatypes.AliasRoutingConfiguration{AdditionalVersionWeights: map[string]float64{"13": 0.1}},
	}
	got, err := lambdaAliasRecord(functionARN, alias, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Resource == nil || got.Resource.ResourceType != "aws_lambda_alias" || got.Resource.ResourceID != aliasARN || got.Resource.ARN != aliasARN || got.Resource.Name != "live" {
		t.Fatalf("alias resource = %+v", got.Resource)
	}
	attributes := got.Resource.Attributes
	if attributes["function_arn"] != functionARN || attributes["function_version"] != "12" || attributes["revision_id"] != "rev-1" || !reflect.DeepEqual(attributes["routing_weights"], map[string]float64{"13": 0.1}) {
		t.Fatalf("alias attributes = %#v", attributes)
	}
	if _, exists := attributes["description"]; exists {
		t.Fatalf("user supplied description leaked: %#v", attributes)
	}
	if got.Relationship == nil || got.Relationship.RelationshipType != "lambda_alias_targets_function" || got.Relationship.SourceARN != aliasARN || got.Relationship.TargetARN != functionARN || got.Relationship.SourceRecordID != aliasARN+"#function#"+functionARN {
		t.Fatalf("alias relationship = %+v", got.Relationship)
	}
}

func TestLambdaAliasRecordRejectsWrongParentAndMissingIdentity(t *testing.T) {
	const functionARN = "arn:aws:lambda:us-east-1:123456789012:function:worker"
	for _, alias := range []lambdatypes.AliasConfiguration{
		{AliasArn: aws.String("arn:aws:lambda:us-east-1:123456789012:function:other:live"), Name: aws.String("live")},
		{AliasArn: aws.String(functionARN + ":prod"), Name: aws.String("live")},
		{AliasArn: aws.String(functionARN + ":prod")},
		{},
	} {
		if _, err := lambdaAliasRecord(functionARN, alias, "us-east-1"); err == nil {
			t.Fatalf("unsafe alias accepted: %+v", alias)
		}
	}
}

func TestLambdaAliasRecordNormalizesRoutingWeights(t *testing.T) {
	const functionARN = "arn:aws:lambda:us-east-1:123456789012:function:worker"
	base := lambdatypes.AliasConfiguration{AliasArn: aws.String(functionARN + ":live"), Name: aws.String("live")}
	for _, test := range []struct {
		name    string
		weights map[string]float64
		want    map[string]float64
	}{
		{name: "absent", weights: nil, want: nil},
		{name: "blank keys", weights: map[string]float64{" ": 0.1}, want: map[string]float64{}},
		{name: "trim and deterministic exact key", weights: map[string]float64{" 13 ": 0.2, "13": 0.1, " ": 0.3}, want: map[string]float64{"13": 0.1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			alias := base
			alias.RoutingConfig = &lambdatypes.AliasRoutingConfiguration{AdditionalVersionWeights: test.weights}
			for range 20 {
				got, err := lambdaAliasRecord(functionARN, alias, "us-east-1")
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got.Resource.Attributes["routing_weights"], test.want) || !reflect.DeepEqual(got.Relationship.Attributes["routing_weights"], test.want) {
					t.Fatalf("routing weights resource=%#v relationship=%#v, want %#v", got.Resource.Attributes["routing_weights"], got.Relationship.Attributes["routing_weights"], test.want)
				}
			}
		})
	}
}
