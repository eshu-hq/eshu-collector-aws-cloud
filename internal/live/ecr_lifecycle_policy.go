// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

type ecrPolicyReader interface {
	GetLifecyclePolicy(context.Context, *awsecr.GetLifecyclePolicyInput, ...func(*awsecr.Options)) (*awsecr.GetLifecyclePolicyOutput, error)
}

// readECRLifecyclePolicy mirrors the legacy not-found exception while failing
// the ECR service on denied or otherwise unsuccessful reads.
func readECRLifecyclePolicy(ctx context.Context, client ecrPolicyReader, repository ecrtypes.Repository, region string) (*collector.Record, error) {
	input := &awsecr.GetLifecyclePolicyInput{RepositoryName: repository.RepositoryName}
	if registry := strings.TrimSpace(aws.ToString(repository.RegistryId)); registry != "" {
		input.RegistryId = aws.String(registry)
	}
	output, err := client.GetLifecyclePolicy(ctx, input)
	var missing *ecrtypes.LifecyclePolicyNotFoundException
	if errors.As(err, &missing) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ecr get lifecycle policy for repository %q: %w", aws.ToString(repository.RepositoryName), err)
	}
	if output == nil {
		return nil, nil
	}
	row := ecrLifecyclePolicyRecord(repository, output, region)
	return &row, nil
}

// ecrLifecyclePolicyRecord emits repository policy metadata without retaining
// the policy JSON body, which can carry user-supplied tag values.
func ecrLifecyclePolicyRecord(repository ecrtypes.Repository, output *awsecr.GetLifecyclePolicyOutput, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(repository.RepositoryArn))
	name := firstECRIdentity(aws.ToString(output.RepositoryName), aws.ToString(repository.RepositoryName))
	registryID := firstECRIdentity(aws.ToString(output.RegistryId), aws.ToString(repository.RegistryId))
	resourceID := firstECRIdentity(arn, name) + "#lifecycle-policy"
	var evaluated any
	if output.LastEvaluatedAt != nil && !output.LastEvaluatedAt.IsZero() {
		evaluated = output.LastEvaluatedAt.UTC()
	}
	return collector.Record{TypedOnly: true, Resource: &collector.LiveResource{
		Region: region, ServiceKind: "ecr", ResourceType: "aws_ecr_lifecycle_policy",
		ResourceID: resourceID, Name: strings.TrimSpace(name) + ":lifecycle-policy",
		Attributes: map[string]any{
			"last_evaluated_at": evaluated, "parent_repository_arn": arn,
			"parent_repository_name": strings.TrimSpace(name), "registry_id": strings.TrimSpace(registryID),
		},
		CorrelationAnchors: []string{resourceID, arn, name}, SourceRecordID: resourceID,
	}}
}
