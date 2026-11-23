// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// Regression for eshu-hq/eshu#11283 leg (b): per-member DescribeServices /
// DescribeTasks Failures must aggregate into services_undescribed /
// tasks_undescribed warning carriers mirroring clusters_undescribed
// (eshu-hq/eshu#11280), never drop silently. Counts and shapes only: no
// account, ARN, or cluster identity appears here.

// TestListECSUndescribedServicesAggregate proves a service ARN that fails
// to describe keeps its surviving sibling behind one aggregated carrier.
func TestListECSUndescribedServicesAggregate(t *testing.T) {
	const prefix = "arn:aws:ecs:us-east-1:123456789012:"
	clusterARN := prefix + "cluster/prod"
	describedARN := prefix + "service/prod/kept"
	missingARN := prefix + "service/prod/dropped"
	calls := map[string]int{}
	cfg := ecsGapStubConfig(t, map[string]any{
		"ListClusters":     map[string]any{"clusterArns": []string{clusterARN}},
		"DescribeClusters": map[string]any{"clusters": []map[string]any{{"clusterArn": clusterARN, "clusterName": "prod"}}},
		"ListServices":     map[string]any{"serviceArns": []string{describedARN, missingARN}},
		"DescribeServices": map[string]any{
			"services": []map[string]any{{"serviceArn": describedARN}},
			"failures": []map[string]any{{"arn": missingARN, "reason": "MISSING", "detail": "Service not found."}},
		},
		"ListTasks": map[string]any{"taskArns": []string{}},
	}, calls)
	records, err := listECS(context.Background(), cfg, ecsGapTestKey(t))
	if err == nil {
		t.Fatal("listECS(undescribed service) error = nil, want a loader warning carrier")
	}
	var denied *optionalReadDenied
	if !errors.As(err, &denied) || len(denied.denials) != 1 {
		t.Fatalf("listECS(undescribed service) error = %v, want one optional denial entry", err)
	}
	entry := denied.denials[0]
	if entry.operation != "DescribeServices" || entry.resource != "region:us-east-1" || entry.effect != "services-undescribed" {
		t.Fatalf("denial identity = %+v, want DescribeServices/region:us-east-1/services-undescribed", entry)
	}
	if entry.warningKind != "services_undescribed" || entry.errorClass != "services_undescribed" {
		t.Fatalf("denial taxonomy = %s/%s, want services_undescribed on both", entry.warningKind, entry.errorClass)
	}
	if entry.attributes["listed_services"] != 2 || entry.attributes["undescribed_services"] != 1 {
		t.Fatalf("denial counts = %v, want listed_services=2 undescribed_services=1", entry.attributes)
	}
	kept := 0
	for _, row := range records {
		if row.Resource != nil && row.Resource.ResourceType == "aws_ecs_service" {
			kept++
		}
	}
	if kept != 1 {
		t.Fatalf("listECS(undescribed service) kept %d service records, want the surviving sibling", kept)
	}
	for _, text := range []string{optionalDenialMessage(entry), fmt.Sprintf("%v", entry.attributes)} {
		if strings.Contains(text, "123456789012") || strings.Contains(text, "service/prod") {
			t.Fatalf("denial carrier leaks identifiers: %q", text)
		}
	}
}

// TestListECSUndescribedTasksAggregate mirrors the services proof for the
// task leg: one failed task aggregates while its sibling still resolves.
func TestListECSUndescribedTasksAggregate(t *testing.T) {
	const prefix = "arn:aws:ecs:us-east-1:123456789012:"
	clusterARN := prefix + "cluster/prod"
	describedARN := prefix + "task/prod/kept"
	missingARN := prefix + "task/prod/dropped"
	cfg := ecsGapStubConfig(t, map[string]any{
		"ListClusters":     map[string]any{"clusterArns": []string{clusterARN}},
		"DescribeClusters": map[string]any{"clusters": []map[string]any{{"clusterArn": clusterARN, "clusterName": "prod"}}},
		"ListServices":     map[string]any{"serviceArns": []string{}},
		"ListTasks":        map[string]any{"taskArns": []string{describedARN, missingARN}},
		"DescribeTasks": map[string]any{
			"tasks":    []map[string]any{{"taskArn": describedARN, "clusterArn": clusterARN, "lastStatus": "RUNNING"}},
			"failures": []map[string]any{{"arn": missingARN, "reason": "MISSING", "detail": "Task not found."}},
		},
	}, map[string]int{})
	records, err := listECS(context.Background(), cfg, ecsGapTestKey(t))
	if err == nil {
		t.Fatal("listECS(undescribed task) error = nil, want a loader warning carrier")
	}
	var denied *optionalReadDenied
	if !errors.As(err, &denied) || len(denied.denials) != 1 {
		t.Fatalf("listECS(undescribed task) error = %v, want one optional denial entry", err)
	}
	entry := denied.denials[0]
	if entry.operation != "DescribeTasks" || entry.resource != "region:us-east-1" || entry.effect != "tasks-undescribed" {
		t.Fatalf("denial identity = %+v, want DescribeTasks/region:us-east-1/tasks-undescribed", entry)
	}
	if entry.warningKind != "tasks_undescribed" || entry.errorClass != "tasks_undescribed" {
		t.Fatalf("denial taxonomy = %s/%s, want tasks_undescribed on both", entry.warningKind, entry.errorClass)
	}
	if entry.attributes["listed_tasks"] != 2 || entry.attributes["undescribed_tasks"] != 1 {
		t.Fatalf("denial counts = %v, want listed_tasks=2 undescribed_tasks=1", entry.attributes)
	}
	kept := 0
	for _, row := range records {
		if row.Resource != nil && row.Resource.ResourceType == "aws_ecs_task" {
			kept++
		}
	}
	if kept != 1 {
		t.Fatalf("listECS(undescribed task) kept %d task records, want the surviving sibling", kept)
	}
	for _, text := range []string{optionalDenialMessage(entry), fmt.Sprintf("%v", entry.attributes)} {
		if strings.Contains(text, "123456789012") || strings.Contains(text, "task/prod") {
			t.Fatalf("denial carrier leaks identifiers: %q", text)
		}
	}
}

// TestListECSCleanMemberWalkWarnsNothing guards the quiet path: a fully
// described service and task walk returns no warning carrier.
func TestListECSCleanMemberWalkWarnsNothing(t *testing.T) {
	const prefix = "arn:aws:ecs:us-east-1:123456789012:"
	clusterARN := prefix + "cluster/prod"
	serviceARN := prefix + "service/prod/kept"
	taskARN := prefix + "task/prod/kept"
	cfg := ecsGapStubConfig(t, map[string]any{
		"ListClusters":     map[string]any{"clusterArns": []string{clusterARN}},
		"DescribeClusters": map[string]any{"clusters": []map[string]any{{"clusterArn": clusterARN, "clusterName": "prod"}}},
		"ListServices":     map[string]any{"serviceArns": []string{serviceARN}},
		"DescribeServices": map[string]any{"services": []map[string]any{{"serviceArn": serviceARN}}, "failures": []any{}},
		"ListTasks":        map[string]any{"taskArns": []string{taskARN}},
		"DescribeTasks":    map[string]any{"tasks": []map[string]any{{"taskArn": taskARN, "clusterArn": clusterARN, "lastStatus": "RUNNING"}}, "failures": []any{}},
	}, map[string]int{})
	records, err := listECS(context.Background(), cfg, ecsGapTestKey(t))
	if err != nil {
		t.Fatalf("listECS(clean members) error = %v, want a warning-free walk", err)
	}
	if len(records) != 3 {
		t.Fatalf("listECS(clean members) kept %d records, want cluster + service + task", len(records))
	}
}

// TestECSMemberGapSurfacesTypedWarningFact proves the leg (b) visibility
// bar: an undescribed service reaches the claim as a typed aws_warning
// fact on a partial result, not merely as status text.
func TestECSMemberGapSurfacesTypedWarningFact(t *testing.T) {
	const account = "123456789012"
	const prefix = "arn:aws:ecs:us-east-1:123456789012:"
	clusterARN := prefix + "cluster/prod"
	describedARN := prefix + "service/prod/kept"
	missingARN := prefix + "service/prod/dropped"
	stub := ecsGapStubConfig(t, map[string]any{
		"ListClusters":     map[string]any{"clusterArns": []string{clusterARN}},
		"DescribeClusters": map[string]any{"clusters": []map[string]any{{"clusterArn": clusterARN, "clusterName": "prod"}}},
		"ListServices":     map[string]any{"serviceArns": []string{describedARN, missingARN}},
		"DescribeServices": map[string]any{
			"services": []map[string]any{{"serviceArn": describedARN}},
			"failures": []map[string]any{{"arn": missingARN, "reason": "MISSING", "detail": "Service not found."}},
		},
		"ListTasks": map[string]any{"taskArns": []string{}},
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
		t.Fatalf("CollectReport(member gap) error = %v, want a degraded outcome", err)
	}
	if len(outcome.Warnings) != 1 || len(outcome.WarningObservations) != 1 {
		t.Fatalf("member-gap outcome: warnings=%v observations=%v, want 1/1", outcome.Warnings, outcome.WarningObservations)
	}
	observation := outcome.WarningObservations[0]
	if observation.WarningKind != "services_undescribed" || observation.Boundary.ServiceKind != "ecs" {
		t.Fatalf("member-gap observation = %+v, want kind services_undescribed on the ecs leg", observation)
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
		t.Fatalf("member-gap result: state=%s warning facts=%d, want partial with one typed warning fact", result.State, warningFacts)
	}
}
