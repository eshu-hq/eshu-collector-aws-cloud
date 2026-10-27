// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"context"
	"strings"
	"time"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/internal/live"
	sdk "github.com/eshu-hq/eshu/sdk/go/collector"
)

// collectLivePlan runs the config-driven live claim: it lists live AWS
// resources for the host's region and service allowlists, builds the source
// report, and runs the existing collector.Collect over it. Services that fail
// degrade to a partial result with a recorded warning; a total read failure
// errors the claim so an empty report never retires good evidence.
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
	if len(outcome.Warnings) == 0 {
		return collector.Collect(plan.claim, outcome.Report, opts)
	}
	return collector.CollectPartial(plan.claim, outcome.Report, opts, strings.Join(outcome.Warnings, "; "))
}
