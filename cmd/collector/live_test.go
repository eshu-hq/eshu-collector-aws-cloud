// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"bytes"
	"encoding/json"
	"github.com/eshu-hq/eshu-collector-aws-cloud/internal/live"
	"github.com/eshu-hq/eshu-sdk/collector/marker"
	"strings"
	"testing"
)

// hostActivationConfig returns the ops-qa host's activation shape: target
// scope, region and service allowlists, and limits -- with no source.input
// file. The live claim path must accept this without demanding a file.
func hostActivationConfig() map[string]any {
	return map[string]any{
		"target_scopes":   map[string]any{"account_id": "055929692761"},
		"allowed_regions": []any{"us-east-1"},
		"allowed_services": []any{
			"iam", "ecr", "ec2", "eks", "elbv2", "route53", "sqs",
			"sns", "eventbridge", "s3", "rds", "dynamodb",
			"cloudwatchlogs", "cloudfront", "apigateway",
			"secretsmanager", "ssm", "ecs", "lambda",
		},
		"limits": map[string]any{
			"maxRecordsPerClaim":  5000.0,
			"maxPayloadBytes":     65536.0,
			"claimTimeoutSeconds": 300.0,
		},
	}
}

func hostActivationRequest(config map[string]any) bytes.Buffer {
	var stdin bytes.Buffer
	request := sdkRequest{
		ProtocolVersion: "collector-sdk/v1alpha1",
		Config:          config,
	}
	if err := json.NewEncoder(&stdin).Encode(request); err != nil {
		panic(err)
	}
	return stdin
}

// TestParseSDKStdioAcceptsLiveConfigWithoutInput proves the reported outage:
// a host activation request that carries target scopes, region/service
// allowlists, and limits -- but no source.input file -- must parse into the
// live-source plan instead of failing with `config "source.input" missing`.
func TestParseSDKStdioAcceptsLiveConfigWithoutInput(t *testing.T) {
	t.Parallel()

	stdin := hostActivationRequest(hostActivationConfig())
	plan, err := parseSDKStdio(&stdin)
	if err != nil {
		t.Fatalf("parseSDKStdio(live config) error = %v, want live-source plan", err)
	}
	if !plan.liveMode {
		t.Fatal("parseSDKStdio(live config) liveMode = false, want true")
	}
	if plan.live.AccountID != "055929692761" {
		t.Fatalf("live.AccountID = %q, want 055929692761", plan.live.AccountID)
	}
	if len(plan.live.Regions) != 1 || plan.live.Regions[0] != "us-east-1" {
		t.Fatalf("live.Regions = %v, want [us-east-1]", plan.live.Regions)
	}
	if len(plan.live.Services) != 19 {
		t.Fatalf("len(live.Services) = %d, want 19", len(plan.live.Services))
	}
	if plan.limits.MaxRecordsPerClaim != 5000 || plan.limits.ClaimTimeoutSeconds != 300 {
		t.Fatalf("limits = %+v, want host limits", plan.limits)
	}
}

// TestParseSDKStdioRejectsUnknownLiveService proves an unknown service name
// fails closed at parse time instead of silently scanning nothing.
func TestParseSDKStdioRejectsUnknownLiveService(t *testing.T) {
	t.Parallel()

	config := hostActivationConfig()
	config["allowed_services"] = []any{"iam", "not-a-service"}
	stdin := hostActivationRequest(config)
	if _, err := parseSDKStdio(&stdin); err == nil {
		t.Fatal("parseSDKStdio(unknown service) error = nil, want failure")
	}
}

// TestParseSDKStdioRejectsLiveConfigWithoutAccount proves a live config with
// no target account fails closed instead of scanning an unbounded scope.
func TestParseSDKStdioRejectsLiveConfigWithoutAccount(t *testing.T) {
	t.Parallel()

	config := hostActivationConfig()
	delete(config, "target_scopes")
	stdin := hostActivationRequest(config)
	_, err := parseSDKStdio(&stdin)
	if err == nil || !strings.Contains(err.Error(), "target_scopes") {
		t.Fatalf("parseSDKStdio(no account) error = %v, want target_scopes failure", err)
	}
}

func TestLiveOptionsIgnoreLegacyPlaceholderDigest(t *testing.T) {
	plan := stdioPlan{}
	plan.live.PreviousDigest = "snapshot:legacy-placeholder-digest"
	opts := liveCollectOptions(plan)
	if opts.PreviousDigest != "" {
		t.Fatalf("live previous digest = %q, want disabled until typed digest covers resources and failures", opts.PreviousDigest)
	}
}

func TestResolveLiveRedactionKeyFailsClosedAndPreservesBytes(t *testing.T) {
	config := live.Config{Services: []string{"lambda", "ecs"}, RedactionKeyEnv: "ESHU_AWS_REDACTION_KEY"}
	calls := 0
	lookup := func(string) (string, bool) {
		calls++
		return "", false
	}
	if _, err := resolveLiveRedactionKey(config, lookup); err == nil || calls != 1 {
		t.Fatalf("missing key: err=%v calls=%d", err, calls)
	}
	for _, material := range []string{"", " \t\n"} {
		if _, err := resolveLiveRedactionKey(config, func(string) (string, bool) { return material, true }); err == nil {
			t.Fatalf("blank key %q accepted", material)
		}
	}
	material := "  accepted key bytes  "
	key, err := resolveLiveRedactionKey(config, func(name string) (string, bool) {
		if name != "ESHU_AWS_REDACTION_KEY" {
			t.Fatalf("lookup name = %q", name)
		}
		return material, true
	})
	if err != nil {
		t.Fatal(err)
	}
	want, err := marker.NewKey([]byte(material))
	if err != nil {
		t.Fatal(err)
	}
	if marker.String("value", "reason", "source", key) != marker.String("value", "reason", "source", want) {
		t.Fatal("accepted key bytes changed")
	}
}
