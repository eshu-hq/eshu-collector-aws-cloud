// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"context"
	"strings"
	"time"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/internal/live"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// collectLivePlan runs a bounded AWS claim and appends typed resource evidence
// from successful service reads. Failed services leave the claim partial.
func collectLivePlan(plan stdioPlan) (sdk.Result, error) {
	outcome, err := live.Collector{AssumeRole: live.AssumeScopeRole}.CollectReport(context.Background(), plan.live)
	if err != nil {
		return sdk.Result{}, err
	}
	opts := liveCollectOptions(plan)
	var result sdk.Result
	if len(outcome.Warnings) == 0 {
		result, err = collector.Collect(plan.claim, outcome.Report, opts)
	} else {
		result, err = collector.CollectPartial(plan.claim, outcome.Report, opts, strings.Join(outcome.Warnings, "; "))
	}
	if err != nil {
		return sdk.Result{}, err
	}
	result, err = collector.AppendLiveResources(result, outcome.Resources, plan.live.SourceURI, plan.live.Limits)
	if err != nil {
		return sdk.Result{}, err
	}
	result, err = collector.AppendLiveRelationships(result, outcome.Relationships, plan.live.SourceURI, plan.live.Limits)
	if err != nil {
		return sdk.Result{}, err
	}
	result, err = collector.AppendLiveImageReferences(result, outcome.ImageReferences, plan.live.SourceURI, plan.live.Limits)
	if err != nil {
		return sdk.Result{}, err
	}
	result, err = collector.AppendLiveS3BucketPostures(result, outcome.S3Postures, plan.live.SourceURI, plan.live.Limits)
	if err != nil {
		return sdk.Result{}, err
	}
	return collector.AppendLiveWarnings(result, outcome.WarningObservations, plan.live.SourceURI, plan.live.Limits)
}

// liveCollectOptions disables placeholder-only freshness until the digest
// includes typed resources and failed service pairs. File mode keeps its
// existing unchanged behavior.
func liveCollectOptions(plan stdioPlan) collector.CollectOptions {
	return collector.CollectOptions{
		ObservedAt: time.Now().UTC(),
		SourceURI:  plan.live.SourceURI,
		Limits:     plan.live.Limits,
	}
}
