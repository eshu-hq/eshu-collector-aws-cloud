// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// Regression for eshu-hq/eshu#11283 leg (a): an ordinary loader failure in
// CollectReport must emit a typed loader_failed warning observation beside
// the historical status-text warning, never instead of it. Counts and
// shapes only: no account, ARN, or cluster identity appears here.

// TestCollectReportEmitsLoaderFailedWarning proves the ordinary-failure
// else branch carries a typed observation with a bounded error class, a
// fixed message template, code-only attributes, and a service:region
// source record ID.
func TestCollectReportEmitsLoaderFailedWarning(t *testing.T) {
	t.Parallel()

	reader := Collector{
		LoadConfig:     fakeConfig(&[]string{}),
		VerifyIdentity: verifiedIdentity,
		Loaders: map[string]Loader{
			"iam": func(_ context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
				return []collector.Record{{ID: "arn:role", Name: "role"}}, nil
			},
			"sqs": func(_ context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
				return nil, &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied by policy"}
			},
		},
	}
	outcome, err := reader.CollectReport(context.Background(), Config{AccountID: "111122223333", Regions: []string{"us-east-1"}, Services: []string{"iam", "sqs"}})
	if err != nil {
		t.Fatalf("CollectReport error = %v, want degraded outcome", err)
	}
	if len(outcome.Report.Records) != 1 {
		t.Fatalf("len(Records) = %d, want 1 surviving record", len(outcome.Report.Records))
	}
	if len(outcome.Warnings) != 1 || !strings.Contains(outcome.Warnings[0], "sqs/us-east-1") {
		t.Fatalf("Warnings = %v, want the historical sqs text warning beside the typed fact", outcome.Warnings)
	}
	if len(outcome.WarningObservations) != 1 {
		t.Fatalf("len(WarningObservations) = %d, want 1 loader_failed observation", len(outcome.WarningObservations))
	}
	got := outcome.WarningObservations[0]
	if got.WarningKind != "loader_failed" || got.ErrorClass != "access_denied" {
		t.Fatalf("warning taxonomy = %s/%s, want loader_failed/access_denied", got.WarningKind, got.ErrorClass)
	}
	if got.Boundary.ServiceKind != "sqs" || got.Boundary.Region != "us-east-1" || got.Boundary.AccountID != "111122223333" {
		t.Fatalf("warning boundary = %+v, want the failed sqs/us-east-1 scope", got.Boundary)
	}
	if got.SourceRecordID != "sqs:us-east-1" {
		t.Fatalf("SourceRecordID = %q, want the service:region pair", got.SourceRecordID)
	}
	wantMessage := "sqs/us-east-1 loader failed (access_denied)"
	if got.Message != wantMessage {
		t.Fatalf("Message = %q, want fixed template %q", got.Message, wantMessage)
	}
	if strings.Contains(got.Message, "denied by policy") {
		t.Fatalf("Message = %q, want the fixed template without raw error text", got.Message)
	}
	if got.Attributes["operation"] == "" || got.Attributes["resource"] == "" || got.Attributes["effect"] == "" {
		t.Fatalf("Attributes = %v, want the operation/resource/effect identity the warning seam requires", got.Attributes)
	}
	if got.Attributes["error_code"] != "AccessDeniedException" {
		t.Fatalf("Attributes = %v, want the smithy error code and nothing else diagnostic", got.Attributes)
	}
}

// TestLoaderErrorClassMapping proves the bounded taxonomy: every smithy
// code maps to one of access_denied, throttled, not_found,
// network_timeout, or loader_error, and non-API failures stay loader_error.
func TestLoaderErrorClassMapping(t *testing.T) {
	t.Parallel()

	cases := []struct{ code, class string }{
		{"AccessDenied", "access_denied"},
		{"AccessDeniedException", "access_denied"},
		{"UnauthorizedOperation", "access_denied"},
		{"ForbiddenException", "access_denied"},
		{"Throttling", "throttled"},
		{"ThrottlingException", "throttled"},
		{"TooManyRequestsException", "throttled"},
		{"SlowDown", "throttled"},
		{"NoSuchEntity", "not_found"},
		{"ResourceNotFoundException", "not_found"},
		{"NotFound", "not_found"},
		{"RequestTimeout", "network_timeout"},
		{"RequestTimeoutException", "network_timeout"},
		{"WeirdNewException", "loader_error"},
		{"", "loader_error"},
	}
	for _, tc := range cases {
		class, code := loaderErrorClass(&smithy.GenericAPIError{Code: tc.code, Message: "shaped"})
		if class != tc.class {
			t.Errorf("loaderErrorClass(%q) = %q, want %q", tc.code, class, tc.class)
		}
		if tc.code != "" && code != tc.code {
			t.Errorf("loaderErrorClass(%q) code = %q, want the raw code carried through", tc.code, code)
		}
	}
	if class, code := loaderErrorClass(errors.New("plain transport failure")); class != "loader_error" || code != "unknown" {
		t.Errorf("loaderErrorClass(plain) = %q/%q, want loader_error/unknown", class, code)
	}
}

// TestLoaderFailedObservationAdmitsWarningFact proves the code-only
// attributes satisfy the warning seam: the observation encodes to one
// typed aws_warning fact on a partial result.
func TestLoaderFailedObservationAdmitsWarningFact(t *testing.T) {
	t.Parallel()

	observation := loaderFailedObservation("sqs", "us-east-1", &smithy.GenericAPIError{Code: "ThrottlingException", Message: "sl slow down"})
	observation.Boundary.AccountID = "111122223333"
	observedAt := time.Now().UTC()
	claim := sdk.Claim{
		ComponentID: collector.ComponentID, InstanceID: "aws-cloud-primary", CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem,
		Scope: sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"}, SourceRunID: "run-1", GenerationID: "generation-1", WorkItemID: "work-1", FencingToken: "fence-1",
		Attempt: 1, Deadline: observedAt.Add(time.Hour), ConfigHandle: "component-config:aws-cloud",
	}
	sourceURI := "aws://111122223333/us-east-1"
	limits := collector.DefaultResourceUse()
	result, err := collector.CollectPartial(claim, collector.Report{GeneratedAt: observedAt, Source: "aws-live:111122223333/us-east-1"}, collector.CollectOptions{ObservedAt: observedAt, SourceURI: sourceURI, Limits: limits}, "sqs/us-east-1: slow down")
	if err != nil {
		t.Fatal(err)
	}
	result, err = collector.AppendLiveWarnings(result, []collector.WarningObservation{observation}, sourceURI, limits)
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
		t.Fatalf("loader_failed result: state=%s warning facts=%d, want partial with one typed warning fact", result.State, warningFacts)
	}
}

// TestPermissionDeniedDefaultsHold guards the historical taxonomy: an
// optional denial without kind overrides still defaults to
// permission_denied on both fields.
func TestPermissionDeniedDefaultsHold(t *testing.T) {
	t.Parallel()

	entry := optionalDenial{operation: "DescribeSecurityGroupRules", resource: "region:us-east-1", effect: "security-group-rules-unavailable"}
	if kind := optionalDenialWarningKind(entry); kind != "permission_denied" {
		t.Fatalf("optionalDenialWarningKind(empty) = %q, want permission_denied", kind)
	}
	if class := optionalDenialErrorClass(entry); class != "permission_denied" {
		t.Fatalf("optionalDenialErrorClass(empty) = %q, want permission_denied", class)
	}
	overridden := optionalDenial{operation: "DescribeClusters", resource: "region:us-east-1", effect: "clusters-undescribed", warningKind: "clusters_undescribed", errorClass: "clusters_undescribed"}
	if kind := optionalDenialWarningKind(overridden); kind != "clusters_undescribed" {
		t.Fatalf("optionalDenialWarningKind(override) = %q, want clusters_undescribed", kind)
	}
	if class := optionalDenialErrorClass(overridden); class != "clusters_undescribed" {
		t.Fatalf("optionalDenialErrorClass(override) = %q, want clusters_undescribed", class)
	}
}

// TestCollectReportFailsWhenAllLegsFailOrdinary guards the hard-error bar:
// total ordinary read loss errors even though each leg now records a typed
// observation, so an empty report never retires good evidence.
func TestCollectReportFailsWhenAllLegsFailOrdinary(t *testing.T) {
	t.Parallel()

	reader := Collector{
		LoadConfig:     fakeConfig(&[]string{}),
		VerifyIdentity: verifiedIdentity,
		Loaders: map[string]Loader{
			"sqs": func(_ context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
				return nil, &smithy.GenericAPIError{Code: "ThrottlingException", Message: "slow down"}
			},
			"iam": func(_ context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
				return nil, errors.New("plain transport failure")
			},
		},
	}
	if _, err := reader.CollectReport(context.Background(), Config{AccountID: "111122223333", Regions: []string{"us-east-1"}, Services: []string{"sqs", "iam"}}); err == nil {
		t.Fatal("CollectReport error = nil, want failure on total ordinary read loss")
	}
}

// TestCollectReportCleanWalkCarriesNoWarnings guards the quiet path: a
// fully successful walk emits no text warnings and no typed observations.
func TestCollectReportCleanWalkCarriesNoWarnings(t *testing.T) {
	t.Parallel()

	reader := Collector{
		LoadConfig:     fakeConfig(&[]string{}),
		VerifyIdentity: verifiedIdentity,
		Loaders: map[string]Loader{
			"iam": func(_ context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
				return []collector.Record{{ID: "arn:role", Name: "role"}}, nil
			},
		},
	}
	outcome, err := reader.CollectReport(context.Background(), Config{AccountID: "111122223333", Regions: []string{"us-east-1"}, Services: []string{"iam"}})
	if err != nil {
		t.Fatalf("CollectReport error = %v, want clean outcome", err)
	}
	if len(outcome.Warnings) != 0 || len(outcome.WarningObservations) != 0 {
		t.Fatalf("clean walk: warnings=%v observations=%v, want zero of both", outcome.Warnings, outcome.WarningObservations)
	}
}
