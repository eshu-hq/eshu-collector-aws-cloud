// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/marker"
)

// Regression for eshu-hq/eshu#11280: ListClusters names a cluster ARN but
// DescribeClusters describes nothing (failures carry MISSING and the
// clusters array stays empty). The loader must surface a warning carrier,
// never a silent (empty, nil) success that commits green with zero ECS
// facts and zero warnings.

// ecsGapStubConfig serves the given ECS operations from memory and counts
// every attempted operation in calls, so the fixture pins which calls the
// loader attempts after an empty describe. ListServices and ListTasks
// answer empty (the live silent shape when children are absent); any other
// unlisted operation fails the test.
func ecsGapStubConfig(t *testing.T, responses map[string]any, calls map[string]int) aws.Config {
	t.Helper()
	transport := ecsRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		target := request.Header.Get("X-Amz-Target")
		operation := target[strings.LastIndex(target, ".")+1:]
		calls[operation]++
		payload, ok := responses[operation]
		if !ok {
			return nil, fmt.Errorf("unexpected ECS operation %q", target)
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: request}, nil
	})
	return aws.Config{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}, RetryMaxAttempts: 1}
}

func ecsGapTestKey(t *testing.T) marker.Key {
	t.Helper()
	key, err := marker.NewKey([]byte("lane-11280-ecs-describe-gap-key"))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestListECSUndescribedClustersWarnInsteadOfSilentEmpty(t *testing.T) {
	const prefix = "arn:aws:ecs:us-east-1:123456789012:"
	clusterARN := prefix + "cluster/prod"
	calls := map[string]int{}
	cfg := ecsGapStubConfig(t, map[string]any{
		"ListClusters": map[string]any{"clusterArns": []string{clusterARN}},
		"DescribeClusters": map[string]any{
			"clusters": []any{},
			"failures": []map[string]any{{"arn": clusterARN, "reason": "MISSING", "detail": "Cluster not found."}},
		},
		"ListServices": map[string]any{"serviceArns": []string{}},
		"ListTasks":    map[string]any{"taskArns": []string{}},
	}, calls)
	records, err := listECS(context.Background(), cfg, ecsGapTestKey(t))
	if err == nil {
		t.Fatal("listECS(undescribed cluster) error = nil, want a loader warning carrier")
	}
	var denied *optionalReadDenied
	if !errors.As(err, &denied) || len(denied.denials) != 1 {
		t.Fatalf("listECS(undescribed cluster) error = %v, want one optional denial entry", err)
	}
	entry := denied.denials[0]
	if entry.operation != "DescribeClusters" || entry.resource != "region:us-east-1" || entry.effect != "clusters-undescribed" {
		t.Fatalf("denial identity = %+v, want DescribeClusters/region:us-east-1/clusters-undescribed", entry)
	}
	if len(records) != 0 {
		t.Fatalf("listECS(undescribed cluster) kept %d records, want none", len(records))
	}
	// Children of an undescribed parent stay unlisted: without a cluster
	// record they cannot be attributed, and attempting them burns API
	// budget only to risk replacing the warning with a hard error.
	for _, operation := range []string{"ListServices", "ListTasks", "DescribeServices", "DescribeTasks", "DescribeTaskDefinition"} {
		if calls[operation] != 0 {
			t.Fatalf("loader attempted %s %d time(s) after the empty describe, want zero", operation, calls[operation])
		}
	}
	// Counts and shapes only: the carrier must never repeat the listed ARN,
	// the dummy account, or the failure detail back at the operator.
	for _, text := range []string{optionalDenialMessage(entry), fmt.Sprintf("%v", entry.attributes)} {
		if strings.Contains(text, "123456789012") || strings.Contains(text, "cluster/prod") {
			t.Fatalf("denial carrier leaks identifiers: %q", text)
		}
	}
}

// TestECSDescribeGapSurfacesTypedWarningFact proves the #11280 warning
// visibility bar: the describe gap reaches the claim as a typed aws_warning
// fact on a partial result, not merely as status text.
func TestECSDescribeGapSurfacesTypedWarningFact(t *testing.T) {
	const account = "123456789012"
	const prefix = "arn:aws:ecs:us-east-1:123456789012:"
	clusterARN := prefix + "cluster/prod"
	stub := ecsGapStubConfig(t, map[string]any{
		"ListClusters": map[string]any{"clusterArns": []string{clusterARN}},
		"DescribeClusters": map[string]any{
			"clusters": []any{},
			"failures": []map[string]any{{"arn": clusterARN, "reason": "MISSING", "detail": "Cluster not found."}},
		},
		"ListServices": map[string]any{"serviceArns": []string{}},
		"ListTasks":    map[string]any{"taskArns": []string{}},
	}, map[string]int{})
	key := ecsGapTestKey(t)
	reader := Collector{
		LoadConfig: fakeConfig(&[]string{}),
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: account, Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{"ecs": func(ctx context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
			return listECS(ctx, stub, key)
		}},
	}
	outcome, err := reader.CollectReport(context.Background(), Config{AccountID: account, Regions: []string{"us-east-1"}, Services: []string{"ecs"}})
	if err != nil {
		t.Fatalf("CollectReport(describe gap) error = %v, want a degraded outcome", err)
	}
	if len(outcome.Resources) != 0 || len(outcome.Warnings) != 1 || len(outcome.WarningObservations) != 1 {
		t.Fatalf("describe-gap outcome: resources=%d warnings=%v observations=%v, want 0/1/1",
			len(outcome.Resources), outcome.Warnings, outcome.WarningObservations)
	}
	observation := outcome.WarningObservations[0]
	if observation.WarningKind != "clusters_undescribed" || observation.Boundary.ServiceKind != "ecs" {
		t.Fatalf("describe-gap observation = %+v, want kind clusters_undescribed on the ecs leg", observation)
	}
	observedAt := time.Now().UTC()
	claim := sdk.Claim{
		ComponentID: collector.ComponentID, InstanceID: "aws-cloud-primary", CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem,
		Scope: sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"}, SourceRunID: "run-1", GenerationID: "generation-1", WorkItemID: "work-1", FencingToken: "fence-1",
		Attempt: 1, Deadline: observedAt.Add(time.Hour), ConfigHandle: "component-config:aws-cloud",
	}
	sourceURI := "aws://123456789012/us-east-1"
	limits := collector.DefaultResourceUse()
	result, err := collector.CollectPartial(claim, outcome.Report, collector.CollectOptions{ObservedAt: observedAt, SourceURI: sourceURI, Limits: limits}, strings.Join(outcome.Warnings, "; "))
	if err != nil {
		t.Fatal(err)
	}
	result, err = collector.AppendLiveWarnings(result, outcome.WarningObservations, sourceURI, limits)
	if err != nil {
		t.Fatal(err)
	}
	warningFacts := 0
	for _, fact := range result.Facts {
		if fact.Kind == collector.AWSKindWarning {
			warningFacts++
		}
	}
	if result.State != sdk.ResultPartial || warningFacts != 1 {
		t.Fatalf("describe-gap result: state=%s warning facts=%d, want partial with one typed warning fact", result.State, warningFacts)
	}
}
