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
	outcome, err := live.Collector{}.CollectReport(context.Background(), plan.live)
	if err != nil {
		return sdk.Result{}, err
	}
	opts := collector.CollectOptions{
		ObservedAt:     time.Now().UTC(),
		SourceURI:      plan.live.SourceURI,
		PreviousDigest: plan.live.PreviousDigest,
		Limits:         plan.live.Limits,
	}
	var result sdk.Result
	if len(outcome.Warnings) == 0 {
		result, err = collector.Collect(plan.claim, outcome.Report, opts)
	} else {
		result, err = collector.CollectPartial(plan.claim, outcome.Report, opts, strings.Join(outcome.Warnings, "; "))
	}
	if err != nil {
		return sdk.Result{}, err
	}
	return collector.AppendLiveResources(result, outcome.Resources, plan.live.SourceURI, plan.live.Limits)
}
