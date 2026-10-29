// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

func TestECRLifecyclePolicyMetadataOmitsPolicyText(t *testing.T) {
	date := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	repository := ecrtypes.Repository{RepositoryArn: aws.String("arn:aws:ecr:us-east-1:123456789012:repository/demo"), RepositoryName: aws.String("demo"), RegistryId: aws.String("123456789012")}
	output := &awsecr.GetLifecyclePolicyOutput{LifecyclePolicyText: aws.String(`{"rules":[{"tagPrefixList":["secret-value"]}]}`), LastEvaluatedAt: &date}
	got := ecrLifecyclePolicyRecord(repository, output, "us-east-1")
	if got.Resource == nil || got.Resource.ResourceID != aws.ToString(repository.RepositoryArn)+"#lifecycle-policy" || got.Resource.ResourceType != "aws_ecr_lifecycle_policy" {
		t.Fatalf("lifecycle policy identity = %#v", got)
	}
	if got.Resource.Attributes["last_evaluated_at"] != date || got.Resource.Attributes["registry_id"] != "123456789012" {
		t.Fatalf("lifecycle policy metadata = %#v", got.Resource.Attributes)
	}
	if _, exists := got.Resource.Attributes["policy_text"]; exists {
		t.Fatalf("raw policy text must not enter resource attributes: %#v", got.Resource.Attributes)
	}
}

type fakeECRPolicyReader struct {
	input  *awsecr.GetLifecyclePolicyInput
	output *awsecr.GetLifecyclePolicyOutput
	err    error
}

func (reader *fakeECRPolicyReader) GetLifecyclePolicy(_ context.Context, input *awsecr.GetLifecyclePolicyInput, _ ...func(*awsecr.Options)) (*awsecr.GetLifecyclePolicyOutput, error) {
	reader.input = input
	return reader.output, reader.err
}

func TestReadECRLifecyclePolicyMissingAndDenied(t *testing.T) {
	repository := ecrtypes.Repository{RepositoryName: aws.String("demo"), RegistryId: aws.String("123456789012")}
	missing := &fakeECRPolicyReader{err: &ecrtypes.LifecyclePolicyNotFoundException{}}
	row, err := readECRLifecyclePolicy(context.Background(), missing, repository, "us-east-1")
	if err != nil || row != nil || aws.ToString(missing.input.RegistryId) != "123456789012" {
		t.Fatalf("missing policy = %#v, err = %v, input = %#v", row, err, missing.input)
	}
	denied := &fakeECRPolicyReader{err: errors.New("access denied")}
	row, err = readECRLifecyclePolicy(context.Background(), denied, repository, "us-east-1")
	if err == nil || row != nil {
		t.Fatalf("denied policy = %#v, err = %v", row, err)
	}
}
