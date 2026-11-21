// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awstagging "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	awsssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// ssmBulkTagResourceTypeFilter scopes the bulk walk to SSM parameters, and
// ssmBulkTagResourcesPerPage takes the API maximum: ceil(parameters/100)
// calls replace one ListTagsForResource call per parameter. Both values are
// pinned by the wave-1 bulk stub (eshu-hq/eshu#11172 S-F shim).
const ssmBulkTagResourceTypeFilter = "ssm:parameter"

const ssmBulkTagResourcesPerPage int32 = 100

// listSSMWithAPIs mirrors the in-tree ssm scanner: parameter metadata only.
// Parameter values, history values, and policy JSON stay unread. Tags arrive
// from one Resource Groups Tagging API walk over the ssm service set instead
// of per-parameter ListTagsForResource calls, then join each Describe row by
// ARN (ARN-less rows rejoin by name suffix). The record count derives from
// DescribeParameters alone, so an untagged parameter keeps its record with
// nil tags.
func listSSMWithAPIs(ctx context.Context, ssmClient *awsssm.Client, taggingClient *awstagging.Client, region string) ([]collector.Record, error) {
	var parameters []ssmtypes.ParameterMetadata
	described := awsssm.NewDescribeParametersPaginator(ssmClient, &awsssm.DescribeParametersInput{})
	for described.HasMorePages() {
		page, err := described.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ssm describe parameters: %w", err)
		}
		parameters = append(parameters, page.Parameters...)
	}
	bulk, err := ssmBulkTagMap(ctx, taggingClient)
	if err != nil {
		return nil, err
	}
	records := make([]collector.Record, 0, len(parameters))
	for _, parameter := range parameters {
		tags, err := ssmBulkTagsForParameter(bulk, aws.ToString(parameter.ARN), aws.ToString(parameter.Name))
		if err != nil {
			return nil, err
		}
		recorded, err := ssmParameterRecord(parameter, tags, region)
		if err != nil {
			return nil, fmt.Errorf("ssm parameter identity: %w", err)
		}
		records = append(records, recorded)
	}
	return records, nil
}

// ssmBulkTagMap walks GetResources over the ssm service set into an
// ARN-keyed tag map. Any walk error (throttle, denial, transport) fails the
// leg with a named error: emitting tag-nil parameters behind a warning would
// be the closed degrade shape (decision 1.4), never a silent fallback, so
// the error stays a plain hard failure and never an optional denial.
//
// GetResources returns only PaginationToken plus ResourceTagMappingList: the
// API has no FailedResourcesMap field (verified against the pinned SDK
// types and the S-F vendor-docs read), so mapping integrity gates here are
// fail-closed on an empty ARN and on a duplicate ARN instead.
func ssmBulkTagMap(ctx context.Context, client *awstagging.Client) (map[string][]ssmtypes.Tag, error) {
	bulk := map[string][]ssmtypes.Tag{}
	pages := awstagging.NewGetResourcesPaginator(client, &awstagging.GetResourcesInput{
		ResourceTypeFilters: []string{ssmBulkTagResourceTypeFilter},
		ResourcesPerPage:    aws.Int32(ssmBulkTagResourcesPerPage),
	})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ssm bulk tags get resources: %w", err)
		}
		for _, mapping := range page.ResourceTagMappingList {
			arn := strings.TrimSpace(aws.ToString(mapping.ResourceARN))
			if arn == "" {
				return nil, fmt.Errorf("ssm bulk tags resource without ARN")
			}
			if _, dup := bulk[arn]; dup {
				return nil, fmt.Errorf("ssm bulk tags duplicate resource %q", arn)
			}
			tags := make([]ssmtypes.Tag, 0, len(mapping.Tags))
			for _, tag := range mapping.Tags {
				tags = append(tags, ssmtypes.Tag{Key: tag.Key, Value: tag.Value})
			}
			bulk[arn] = tags
		}
	}
	return bulk, nil
}

// ssmBulkTagsForParameter resolves the bulk tag list for one Describe row.
// An exact ARN match wins; a row without an ARN (the fixture's parameter-C
// shape) rejoins by the ":parameter"+name suffix the tagging API's ARN
// carries. Absence on both paths means untagged-by-absence and returns nil
// with no call. Several suffix matches fail the leg: the join would be
// ambiguous. Mapping through ssmParameterTags at the call site keeps the
// single trim/blank-drop/nil shape.
func ssmBulkTagsForParameter(bulk map[string][]ssmtypes.Tag, arn, name string) ([]ssmtypes.Tag, error) {
	arn = strings.TrimSpace(arn)
	if arn != "" {
		return bulk[arn], nil
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil
	}
	suffix := ":parameter" + name
	if !strings.HasPrefix(name, "/") {
		suffix = ":parameter/" + name
	}
	matched := ""
	for candidate := range bulk {
		if strings.HasSuffix(candidate, suffix) {
			if matched != "" {
				return nil, fmt.Errorf("ssm bulk tags ambiguous join for parameter %q", name)
			}
			matched = candidate
		}
	}
	if matched == "" {
		return nil, nil
	}
	return bulk[matched], nil
}
