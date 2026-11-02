// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/internal/live"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/marker"
)

// collectLivePlan runs a bounded AWS claim and appends typed resource evidence
// from successful service reads. Failed services leave the claim partial.
// It also reports the typed-evidence digest so freshness keys off typed
// facts instead of the transitional snapshot fact; a previous digest that
// matches short-circuits to unchanged with no facts.
func collectLivePlan(plan stdioPlan) (sdk.Result, string, error) {
	return collectLivePlanWithLookup(plan, os.LookupEnv)
}

func collectLivePlanWithLookup(plan stdioPlan, lookup func(string) (string, bool)) (sdk.Result, string, error) {
	key, err := resolveLiveRedactionKey(plan.live, lookup)
	if err != nil {
		return sdk.Result{}, "", err
	}
	plan.live.RedactionKey = key
	outcome, err := live.Collector{AssumeRole: live.AssumeScopeRole}.CollectReport(context.Background(), plan.live)
	if err != nil {
		return sdk.Result{}, "", err
	}
	opts := liveCollectOptions(plan)
	var result sdk.Result
	if len(outcome.Warnings) == 0 {
		result, err = collector.Collect(plan.claim, outcome.Report, opts)
	} else {
		result, err = collector.CollectPartial(plan.claim, outcome.Report, opts, strings.Join(outcome.Warnings, "; "))
	}
	if err != nil {
		return sdk.Result{}, "", err
	}
	result, outcomeDigest, err := live.AppendOutcomeFacts(result, outcome, plan.live.SourceURI, plan.live.Limits)
	if err != nil {
		return sdk.Result{}, "", err
	}
	if unchanged, done := unchangedOutcome(plan.claim, plan.live.PreviousDigest, outcomeDigest); done {
		return unchanged, "", nil
	}
	return result, outcomeDigest, nil
}

// resolveLiveRedactionKey obtains deployment key material only at the command
// boundary, and only when a selected service redacts scanner-side (currently
// ECS). The activation names the fixed environment variable, never its value.
func resolveLiveRedactionKey(config live.Config, lookup func(string) (string, bool)) (marker.Key, error) {
	needsKey := false
	for _, service := range config.Services {
		if service == "ecs" {
			needsKey = true
		}
	}
	if !needsKey {
		return marker.Key{}, nil
	}
	if config.RedactionKeyEnv != "ESHU_AWS_REDACTION_KEY" {
		return marker.Key{}, fmt.Errorf("live ecs requires source.redactionKeyEnv reference")
	}
	raw, present := lookup(config.RedactionKeyEnv)
	if !present {
		return marker.Key{}, fmt.Errorf("live ecs requires ESHU_AWS_REDACTION_KEY")
	}
	key, err := marker.NewKey([]byte(raw))
	if err != nil || key.IsZero() {
		return marker.Key{}, fmt.Errorf("live ecs requires nonblank ESHU_AWS_REDACTION_KEY")
	}
	return key, nil
}

// liveCollectOptions drops the placeholder previous digest: live freshness
// compares the typed-evidence digest at the plan level instead (see
// unchangedOutcome), so the report-digest short-circuit in Collect never
// fires on the live path. File mode keeps its existing unchanged behavior.
func liveCollectOptions(plan stdioPlan) collector.CollectOptions {
	return collector.CollectOptions{
		ObservedAt: time.Now().UTC(),
		SourceURI:  plan.live.SourceURI,
		Limits:     plan.live.Limits,
	}
}
