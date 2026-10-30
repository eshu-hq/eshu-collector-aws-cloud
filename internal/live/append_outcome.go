// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// AppendOutcomeFacts appends every typed observation family in one
// Outcome to result, in the single order production relies on. Both
// cmd/collector/collectLivePlan and the pipeline parity test call this
// function, so deleting or reordering an appender here fails the test
// instead of silently dropping a fact family in production.
func AppendOutcomeFacts(result sdk.Result, outcome Outcome, sourceURI string, limits collector.ResourceUse) (sdk.Result, error) {
	var err error
	if result, err = collector.AppendLiveResources(result, outcome.Resources, sourceURI, limits); err != nil {
		return result, err
	}
	if result, err = collector.AppendLiveRelationships(result, outcome.Relationships, sourceURI, limits); err != nil {
		return result, err
	}
	if result, err = collector.AppendLiveImageReferences(result, outcome.ImageReferences, sourceURI, limits); err != nil {
		return result, err
	}
	if result, err = collector.AppendLiveS3BucketPostures(result, outcome.S3Postures, sourceURI, limits); err != nil {
		return result, err
	}
	if result, err = collector.AppendLiveSecurityGroupRulePostures(result, outcome.SGPostures, sourceURI, limits); err != nil {
		return result, err
	}
	if result, err = collector.AppendLiveEC2InstancePostures(result, outcome.EC2Postures, sourceURI, limits); err != nil {
		return result, err
	}
	return collector.AppendLiveWarnings(result, outcome.WarningObservations, sourceURI, limits)
}
