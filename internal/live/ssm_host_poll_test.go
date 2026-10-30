// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/smithy-go"
)

// fakeSSMInventoryAPI replays scripted discovery and inventory pages without
// a network. Every response is dated and coherent unless the test mutates it.
type fakeSSMInventoryAPI struct {
	instances map[string]ssmtypes.InstanceInformation
	streams   map[string]*fakeInventoryStream
	denyList  map[string]bool
	denyDII   bool
	// foreignType forces the listed hosts to answer a non-application
	// inventory type, proving foreign rows never become observations.
	foreignType map[string]bool
	// wrongInstance forces the listed hosts to answer inventory pages
	// keyed by another host's id, proving a wrong-instance stream is
	// partial and never a successful empty capture.
	wrongInstance map[string]string
}

type fakeInventoryStream struct {
	capture string
	schema  string
	pages   [][]map[string]string
}

func (f *fakeSSMInventoryAPI) DescribeInstanceInformation(ctx context.Context, params *awsssm.DescribeInstanceInformationInput, optFns ...func(*awsssm.Options)) (*awsssm.DescribeInstanceInformationOutput, error) {
	if f.denyDII {
		return nil, fakeDenied("DescribeInstanceInformation")
	}
	out := &awsssm.DescribeInstanceInformationOutput{}
	for _, info := range f.instances {
		id := aws.ToString(info.InstanceId)
		if len(params.Filters) > 0 {
			want := false
			for _, filter := range params.Filters {
				for _, value := range filter.Values {
					if value == id {
						want = true
					}
				}
			}
			if !want {
				continue
			}
		}
		out.InstanceInformationList = append(out.InstanceInformationList, info)
	}
	return out, nil
}

func (f *fakeSSMInventoryAPI) ListInventoryEntries(ctx context.Context, params *awsssm.ListInventoryEntriesInput, optFns ...func(*awsssm.Options)) (*awsssm.ListInventoryEntriesOutput, error) {
	id := aws.ToString(params.InstanceId)
	if f.denyList[id] {
		return nil, fakeDenied("ListInventoryEntries")
	}
	stream, ok := f.streams[id]
	if !ok {
		return &awsssm.ListInventoryEntriesOutput{
			InstanceId: params.InstanceId, TypeName: params.TypeName,
		}, nil
	}
	token := aws.ToString(params.NextToken)
	index := 0
	if token != "" {
		if _, err := fmt.Sscanf(token, "page-%d", &index); err != nil || index <= 0 || index >= len(stream.pages) {
			return nil, fmt.Errorf("unknown pagination token")
		}
	}
	typeName := params.TypeName
	if f.foreignType[id] {
		typeName = aws.String("AWS:File")
	}
	instanceID := params.InstanceId
	if wrong, ok := f.wrongInstance[id]; ok {
		instanceID = aws.String(wrong)
	}
	out := &awsssm.ListInventoryEntriesOutput{
		InstanceId: instanceID, TypeName: typeName,
		CaptureTime: captureOrNil(stream.capture), SchemaVersion: aws.String(stream.schema),
		Entries: stream.pages[index],
	}
	if index+1 < len(stream.pages) {
		out.NextToken = aws.String(fmt.Sprintf("page-%d", index+1))
	}
	return out, nil
}

// captureOrNil mirrors the API: an undated response carries a nil
// CaptureTime, never an empty string.
func captureOrNil(capture string) *string {
	if capture == "" {
		return nil
	}
	return aws.String(capture)
}

// fakeDenied builds a client-fault denial shaped like the SSM
// AccessDeniedException the measurement identity received.
func fakeDenied(op string) error {
	return &smithy.GenericAPIError{Code: "AccessDeniedException", Message: op + ": denied", Fault: smithy.FaultUnknown}
}

func ssmFakeInstance(id string) ssmtypes.InstanceInformation {
	return ssmtypes.InstanceInformation{
		InstanceId:      aws.String(id),
		PingStatus:      ssmtypes.PingStatusOnline,
		ResourceType:    ssmtypes.ResourceTypeEc2Instance,
		PlatformType:    ssmtypes.PlatformTypeLinux,
		PlatformName:    aws.String("ExampleLinux"),
		PlatformVersion: aws.String("1.0"),
	}
}

// ssmFakePages builds a coherent dated stream of full 50-row pages plus a
// final partial page, mirroring the measured 26-27-page populated hosts.
func ssmFakePages(id string, count int, capture string) [][]map[string]string {
	pages := [][]map[string]string{}
	row := 0
	for len(pages) == 0 || row < count {
		page := []map[string]string{}
		for len(page) < 50 && row < count {
			page = append(page, map[string]string{
				"Name":         fmt.Sprintf("example-agent-%d", row),
				"Version":      "1.0.0",
				"Release":      "1.example",
				"Epoch":        "0",
				"PackageId":    fmt.Sprintf("example-agent-%d-1.0.0-1.example.x86_64", row),
				"Architecture": "x86_64",
				"URL":          "https://example.invalid/pkg",
				"Summary":      "must never be stored",
			})
			row++
		}
		pages = append(pages, page)
	}
	return pages
}

func ssmTestIdentity() VerifiedIdentity {
	return VerifiedIdentity{AccountID: "000000000001", Partition: "aws"}
}

func ssmPollNow() time.Time {
	return time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
}

func TestPollSSMHostInventoryAdmitsMeasuredCohort(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := ssmPollNow()
	capture := now.Add(-2 * time.Minute).Format(time.RFC3339)
	api := &fakeSSMInventoryAPI{
		instances: map[string]ssmtypes.InstanceInformation{
			"i-00000000000000001": ssmFakeInstance("i-00000000000000001"),
			"i-00000000000000002": ssmFakeInstance("i-00000000000000002"),
		},
		streams: map[string]*fakeInventoryStream{
			"i-00000000000000001": {capture: capture, schema: "1.0", pages: ssmFakePages("a", 1310, capture)},
			"i-00000000000000002": {capture: capture, schema: "1.0", pages: ssmFakePages("b", 1295, capture)},
		},
	}
	limits := ssmTestLimits()
	limits.Targets = []string{"i-00000000000000001", "i-00000000000000002"}
	report, err := PollSSMHostInventory(ctx, api, ssmTestIdentity(), "us-east-1", limits, NewSSMCaptureTracker(), now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Aggregates.Targets != 2 || report.Aggregates.Managed != 2 || report.Aggregates.Captured != 2 {
		t.Fatalf("cohort counts changed: %+v", report.Aggregates)
	}
	if report.Aggregates.SuccessfulHosts != 2 || report.Aggregates.Outcome != SSMHostInventorySuccessful {
		t.Fatalf("cohort outcome changed: %+v", report.Aggregates)
	}
	if report.Aggregates.Entries != 2605 || report.Aggregates.Pages != 53 {
		t.Fatalf("cohort volume changed: %+v", report.Aggregates)
	}
	if len(report.Applications) != 2605 {
		t.Fatalf("application observations = %d, want 2605", len(report.Applications))
	}
	if len(report.Platforms) != 2 {
		t.Fatalf("platform observations = %d, want 2", len(report.Platforms))
	}
	for _, app := range report.Applications {
		if app.SourceType != "AWS:Application" || app.CaptureTime != capture {
			t.Fatalf("application observation changed: %+v", app)
		}
	}
	seen := map[string]struct{}{}
	for _, app := range report.Applications {
		key := app.InstanceID + "\x00" + derefTestString(app.Name)
		if _, dup := seen[key]; dup {
			t.Fatalf("duplicate row admitted for %q", key)
		}
		seen[key] = struct{}{}
	}
}

func derefTestString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func TestPollSSMHostInventorySuppressesUnchangedCapture(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := ssmPollNow()
	capture := now.Add(-2 * time.Minute).Format(time.RFC3339)
	api := &fakeSSMInventoryAPI{
		instances: map[string]ssmtypes.InstanceInformation{
			"i-00000000000000001": ssmFakeInstance("i-00000000000000001"),
		},
		streams: map[string]*fakeInventoryStream{
			"i-00000000000000001": {capture: capture, schema: "1.0", pages: ssmFakePages("a", 60, capture)},
		},
	}
	limits := ssmTestLimits()
	tracker := NewSSMCaptureTracker()
	first, err := PollSSMHostInventory(ctx, api, ssmTestIdentity(), "us-east-1", limits, tracker, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Applications) != 60 {
		t.Fatalf("first poll applications = %d, want 60", len(first.Applications))
	}
	second, err := PollSSMHostInventory(ctx, api, ssmTestIdentity(), "us-east-1", limits, tracker, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Applications) != 0 {
		t.Fatalf("repeat poll emitted %d application observations, want suppression", len(second.Applications))
	}
	if second.Aggregates.SuppressedHosts != 1 || second.Aggregates.Outcome != SSMHostInventorySuccessful {
		t.Fatalf("repeat poll telemetry changed: %+v", second.Aggregates)
	}
	if len(second.Platforms) != 1 {
		t.Fatalf("repeat poll dropped the fresh platform observation: %+v", second.Aggregates)
	}
	// A fresh capture on the same host emits again through the same tracker.
	later := now.Add(25 * time.Hour).Format(time.RFC3339)
	api.streams["i-00000000000000001"] = &fakeInventoryStream{capture: later, schema: "1.0", pages: ssmFakePages("a", 60, later)}
	third, err := PollSSMHostInventory(ctx, api, ssmTestIdentity(), "us-east-1", limits, tracker, now.Add(25*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(third.Applications) != 60 || third.Aggregates.SuppressedHosts != 0 {
		t.Fatalf("new capture was suppressed: %+v", third.Aggregates)
	}
}

func TestPollSSMHostInventoryPartialVectors(t *testing.T) {
	t.Parallel()
	now := ssmPollNow()
	capture := now.Add(-2 * time.Minute).Format(time.RFC3339)
	freshLimits := func(targets ...string) SSMHostInventoryLimits {
		limits := ssmTestLimits()
		limits.Targets = targets
		return limits
	}
	t.Run("undated is unknown", func(t *testing.T) {
		t.Parallel()
		api := &fakeSSMInventoryAPI{
			instances: map[string]ssmtypes.InstanceInformation{"i-u": ssmFakeInstance("i-u")},
			streams:   map[string]*fakeInventoryStream{"i-u": {capture: "", schema: "1.0", pages: ssmFakePages("u", 10, "")}},
		}
		report, err := PollSSMHostInventory(context.Background(), api, ssmTestIdentity(), "us-east-1", freshLimits("i-u"), NewSSMCaptureTracker(), now)
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Applications) != 0 || report.Aggregates.PartialHosts != 1 {
			t.Fatalf("undated stream emitted: %+v", report.Aggregates)
		}
	})
	t.Run("denied list is denied", func(t *testing.T) {
		t.Parallel()
		api := &fakeSSMInventoryAPI{
			instances: map[string]ssmtypes.InstanceInformation{"i-d": ssmFakeInstance("i-d")},
			streams:   map[string]*fakeInventoryStream{},
			denyList:  map[string]bool{"i-d": true},
		}
		report, err := PollSSMHostInventory(context.Background(), api, ssmTestIdentity(), "us-east-1", freshLimits("i-d"), NewSSMCaptureTracker(), now)
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Applications) != 0 || report.Aggregates.DeniedHosts != 1 || report.Aggregates.Outcome != SSMHostInventoryDenied {
			t.Fatalf("denial misclassified: %+v", report.Aggregates)
		}
	})
	t.Run("non-ec2 and offline are excluded", func(t *testing.T) {
		t.Parallel()
		managed := ssmFakeInstance("i-managed")
		managed.ResourceType = ssmtypes.ResourceTypeManagedInstance
		offline := ssmFakeInstance("i-offline")
		offline.PingStatus = ssmtypes.PingStatusConnectionLost
		api := &fakeSSMInventoryAPI{
			instances: map[string]ssmtypes.InstanceInformation{"i-managed": managed, "i-offline": offline},
			streams:   map[string]*fakeInventoryStream{},
		}
		report, err := PollSSMHostInventory(context.Background(), api, ssmTestIdentity(), "us-east-1", freshLimits("i-managed", "i-offline", "i-ghost"), NewSSMCaptureTracker(), now)
		if err != nil {
			t.Fatal(err)
		}
		if report.Aggregates.Excluded != 3 || len(report.Applications) != 0 {
			t.Fatalf("exclusion miscounted: %+v", report.Aggregates)
		}
		if report.Aggregates.Outcome != SSMHostInventoryPartial {
			t.Fatalf("all-excluded poll outcome = %q, want partial: %+v", report.Aggregates.Outcome, report.Aggregates)
		}
	})
	t.Run("stale capture displays stale", func(t *testing.T) {
		t.Parallel()
		old := now.Add(-3 * time.Hour).Format(time.RFC3339)
		api := &fakeSSMInventoryAPI{
			instances: map[string]ssmtypes.InstanceInformation{"i-s": ssmFakeInstance("i-s")},
			streams:   map[string]*fakeInventoryStream{"i-s": {capture: old, schema: "1.0", pages: ssmFakePages("s", 10, old)}},
		}
		report, err := PollSSMHostInventory(context.Background(), api, ssmTestIdentity(), "us-east-1", freshLimits("i-s"), NewSSMCaptureTracker(), now)
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Applications) != 0 || report.Aggregates.StaleHosts != 1 || report.Aggregates.Outcome != SSMHostInventoryStale {
			t.Fatalf("stale misclassified: %+v", report.Aggregates)
		}
	})
	t.Run("ceiling breach never supersedes", func(t *testing.T) {
		t.Parallel()
		limits := freshLimits("i-c")
		limits.MaxEntriesPerHostPerCapture = 5000
		many := ssmFakePages("c", 5001, capture)
		api := &fakeSSMInventoryAPI{
			instances: map[string]ssmtypes.InstanceInformation{"i-c": ssmFakeInstance("i-c")},
			streams:   map[string]*fakeInventoryStream{"i-c": {capture: capture, schema: "1.0", pages: many}},
		}
		report, err := PollSSMHostInventory(context.Background(), api, ssmTestIdentity(), "us-east-1", limits, NewSSMCaptureTracker(), now)
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Applications) != 0 || report.Aggregates.PartialHosts != 1 || report.Aggregates.Outcome != SSMHostInventoryPartial {
			t.Fatalf("ceiling breach superseded: %+v", report.Aggregates)
		}
	})
	t.Run("host cap defers deterministically", func(t *testing.T) {
		t.Parallel()
		limits := freshLimits("i-b", "i-a")
		limits.MaxHostsPerPoll = 1
		api := &fakeSSMInventoryAPI{
			instances: map[string]ssmtypes.InstanceInformation{
				"i-a": ssmFakeInstance("i-a"),
				"i-b": ssmFakeInstance("i-b"),
			},
			streams: map[string]*fakeInventoryStream{
				"i-a": {capture: capture, schema: "1.0", pages: ssmFakePages("a", 5, capture)},
				"i-b": {capture: capture, schema: "1.0", pages: ssmFakePages("b", 5, capture)},
			},
		}
		report, err := PollSSMHostInventory(context.Background(), api, ssmTestIdentity(), "us-east-1", limits, NewSSMCaptureTracker(), now)
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Applications) != 5 || report.Aggregates.PartialHosts != 1 {
			t.Fatalf("host cap misapplied: %+v", report.Aggregates)
		}
		if len(report.Hosts) != 2 || report.Hosts[0].InstanceID != "i-a" || report.Hosts[1].InstanceID != "i-b" {
			t.Fatalf("deferred host is not the sorted remainder: %+v", report.Hosts)
		}
		if report.Hosts[0].Outcome != SSMHostInventorySuccessful || report.Hosts[1].Outcome != SSMHostInventoryPartial {
			t.Fatalf("deferred host misclassified: %+v", report.Hosts)
		}
	})
	t.Run("denied discovery denies every target", func(t *testing.T) {
		t.Parallel()
		api := &fakeSSMInventoryAPI{denyDII: true}
		report, err := PollSSMHostInventory(context.Background(), api, ssmTestIdentity(), "us-east-1", freshLimits("i-x"), NewSSMCaptureTracker(), now)
		if err != nil {
			t.Fatal(err)
		}
		if report.Aggregates.DeniedHosts != 1 || len(report.Applications) != 0 {
			t.Fatalf("discovery denial misclassified: %+v", report.Aggregates)
		}
	})
	t.Run("foreign inventory type never becomes observations", func(t *testing.T) {
		t.Parallel()
		api := &fakeSSMInventoryAPI{
			instances:   map[string]ssmtypes.InstanceInformation{"i-f": ssmFakeInstance("i-f")},
			streams:     map[string]*fakeInventoryStream{"i-f": {capture: capture, schema: "1.0", pages: ssmFakePages("f", 10, capture)}},
			foreignType: map[string]bool{"i-f": true},
		}
		report, err := PollSSMHostInventory(context.Background(), api, ssmTestIdentity(), "us-east-1", freshLimits("i-f"), NewSSMCaptureTracker(), now)
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Applications) != 0 || report.Aggregates.PartialHosts != 1 || report.Aggregates.Outcome != SSMHostInventoryPartial {
			t.Fatalf("foreign stream emitted observations: %+v", report.Aggregates)
		}
		if len(report.Hosts) != 1 || report.Hosts[0].Reason != ssmCaptureReasonSourceNotAllowlisted {
			t.Fatalf("foreign stream reason = %+v, want the allowlist verdict", report.Hosts)
		}
	})
	t.Run("wrong-instance page is partial, never successful", func(t *testing.T) {
		t.Parallel()
		tracker := NewSSMCaptureTracker()
		api := &fakeSSMInventoryAPI{
			instances:     map[string]ssmtypes.InstanceInformation{"i-w": ssmFakeInstance("i-w")},
			streams:       map[string]*fakeInventoryStream{"i-w": {capture: capture, schema: "1.0", pages: ssmFakePages("w", 10, capture)}},
			wrongInstance: map[string]string{"i-w": "i-other"},
		}
		report, err := PollSSMHostInventory(context.Background(), api, ssmTestIdentity(), "us-east-1", freshLimits("i-w"), tracker, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Applications) != 0 || len(report.Platforms) != 0 {
			t.Fatalf("wrong-instance stream emitted: %+v", report.Aggregates)
		}
		if report.Aggregates.PartialHosts != 1 || report.Aggregates.SuccessfulHosts != 0 || report.Aggregates.Outcome != SSMHostInventoryPartial {
			t.Fatalf("wrong-instance stream misclassified: %+v", report.Aggregates)
		}
		if len(report.Hosts) != 1 || report.Hosts[0].Reason != ssmCaptureReasonMissing {
			t.Fatalf("wrong-instance reason = %+v, want the missing-capture verdict", report.Hosts)
		}
		if tracker.IsRepeat("i-w", capture) {
			t.Fatal("wrong-instance stream marked the tracker")
		}
	})
	t.Run("denied discovery with host cap denies polled, defers remainder", func(t *testing.T) {
		t.Parallel()
		limits := freshLimits("i-a", "i-b")
		limits.MaxHostsPerPoll = 1
		api := &fakeSSMInventoryAPI{denyDII: true}
		report, err := PollSSMHostInventory(context.Background(), api, ssmTestIdentity(), "us-east-1", limits, NewSSMCaptureTracker(), now)
		if err != nil {
			t.Fatal(err)
		}
		if report.Aggregates.DeniedHosts != 1 || report.Aggregates.PartialHosts != 1 {
			t.Fatalf("denial with deferral miscounted: %+v", report.Aggregates)
		}
		if len(report.Hosts) != 2 || report.Hosts[0].InstanceID != "i-a" || report.Hosts[1].InstanceID != "i-b" {
			t.Fatalf("denial with deferral misordered: %+v", report.Hosts)
		}
		if report.Hosts[0].Outcome != SSMHostInventoryDenied || report.Hosts[1].Outcome != SSMHostInventoryPartial || report.Hosts[1].Reason != ssmCaptureReasonDeferred {
			t.Fatalf("denial with deferral misclassified: %+v", report.Hosts)
		}
		if report.Aggregates.Outcome != SSMHostInventoryDenied {
			t.Fatalf("denial with deferral outcome = %q, want denied: %+v", report.Aggregates.Outcome, report.Aggregates)
		}
	})
	t.Run("missing limits fail closed", func(t *testing.T) {
		t.Parallel()
		api := &fakeSSMInventoryAPI{}
		if _, err := PollSSMHostInventory(context.Background(), api, ssmTestIdentity(), "us-east-1", SSMHostInventoryLimits{}, NewSSMCaptureTracker(), now); err == nil {
			t.Fatal("unconfigured poll was accepted")
		}
	})
}
