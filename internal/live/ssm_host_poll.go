// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/smithy-go"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// // PollSSMHostInventory runs one bounded SSM application collection pass
// over the explicit configured targets: filtered discovery, complete
// pagination per host before any supersession, fail-closed ceilings, and
// unchanged-capture suppression through the tracker. It performs reads
// only; association lifecycle stays outside the collector.
func PollSSMHostInventory(ctx context.Context, api SSMInventoryAPI, identity VerifiedIdentity, region string, limits SSMHostInventoryLimits, tracker *SSMCaptureTracker, now time.Time) (SSMHostPollReport, error) {
	if err := limits.Validate(); err != nil {
		return SSMHostPollReport{}, err
	}
	if strings.TrimSpace(region) == "" {
		return SSMHostPollReport{}, fmt.Errorf("ssm host inventory: region is required")
	}
	now = now.UTC()
	seenTargets := make(map[string]struct{}, len(limits.Targets))
	targets := make([]string, 0, len(limits.Targets))
	for _, target := range limits.Targets {
		trimmed := strings.TrimSpace(target)
		if _, dup := seenTargets[trimmed]; dup {
			continue
		}
		seenTargets[trimmed] = struct{}{}
		targets = append(targets, trimmed)
	}
	sort.Strings(targets)
	report := SSMHostPollReport{Aggregates: SSMHostInventoryAggregates{Targets: len(targets)}}
	polled := targets
	deferred := []string{}
	if len(targets) > limits.MaxHostsPerPoll {
		polled = targets[:limits.MaxHostsPerPoll]
		deferred = targets[limits.MaxHostsPerPoll:]
	}
	discovered, err := discoverSSMManagedNodes(ctx, api, polled)
	if err != nil {
		if isSSMDenial(err) {
			for _, id := range targets {
				report.Hosts = append(report.Hosts, SSMHostPollResult{InstanceID: id, Outcome: SSMHostInventoryDenied, Reason: ssmCaptureReasonDenied})
				report.Aggregates.DeniedHosts++
			}
			report.Aggregates.Outcome = SSMHostInventoryDenied
			return report, nil
		}
		return SSMHostPollReport{}, fmt.Errorf("ssm host inventory: discover managed nodes: %w", err)
	}
	for _, id := range polled {
		var info *ssmtypes.InstanceInformation
		if found, ok := discovered[id]; ok {
			info = &found
		}
		result := pollSSMHost(ctx, api, identity, region, id, info, limits, tracker, now, &report)
		report.Hosts = append(report.Hosts, result)
	}
	for _, id := range deferred {
		report.Hosts = append(report.Hosts, SSMHostPollResult{InstanceID: id, Outcome: SSMHostInventoryPartial, Reason: ssmCaptureReasonDeferred})
		report.Aggregates.PartialHosts++
	}
	// Excluded hosts carry no outcome and do not vote; otherwise denied
	// outranks partial, partial outranks stale, and any success carries.
	outcome := SSMHostInventorySuccessful
	seen := false
	for _, host := range report.Hosts {
		switch host.Outcome {
		case SSMHostInventoryDenied:
			outcome, seen = SSMHostInventoryDenied, true
		case SSMHostInventoryPartial:
			if outcome != SSMHostInventoryDenied {
				outcome, seen = SSMHostInventoryPartial, true
			}
		case SSMHostInventoryStale:
			if outcome != SSMHostInventoryDenied && outcome != SSMHostInventoryPartial {
				outcome, seen = SSMHostInventoryStale, true
			}
		case SSMHostInventorySuccessful:
			seen = true
		}
	}
	if seen {
		report.Aggregates.Outcome = outcome
	} else {
		report.Aggregates.Outcome = SSMHostInventorySuccessful
	}
	return report, nil
}

// discoverSSMManagedNodes reads the filtered DescribeInstanceInformation
// stream for exactly the polled targets. A denial fails the whole pass
// closed: without discovery no host is managed and nothing supersedes.
func discoverSSMManagedNodes(ctx context.Context, api SSMInventoryAPI, targets []string) (map[string]ssmtypes.InstanceInformation, error) {
	index := make(map[string]ssmtypes.InstanceInformation, len(targets))
	var token *string
	for pages := 0; ; pages++ {
		out, err := api.DescribeInstanceInformation(ctx, &awsssm.DescribeInstanceInformationInput{
			Filters:    []ssmtypes.InstanceInformationStringFilter{{Key: aws.String("InstanceIds"), Values: targets}},
			MaxResults: aws.Int32(SSMHostInventoryPageSize),
			NextToken:  token,
		})
		if err != nil {
			return nil, err
		}
		for _, info := range out.InstanceInformationList {
			id := strings.TrimSpace(aws.ToString(info.InstanceId))
			if id != "" {
				index[id] = info
			}
		}
		if aws.ToString(out.NextToken) == "" {
			return index, nil
		}
		if pages+1 >= ssmHostDiscoveryMaxPages {
			return nil, fmt.Errorf("ssm host inventory: managed-node discovery truncated")
		}
		token = out.NextToken
	}
}

// pollSSMHost pages one host's AWS:Application inventory to completion,
// assesses the stream, and appends admitted observations to the report. It
// returns the host verdict and updates the aggregates.
func pollSSMHost(ctx context.Context, api SSMInventoryAPI, identity VerifiedIdentity, region, id string, info *ssmtypes.InstanceInformation, limits SSMHostInventoryLimits, tracker *SSMCaptureTracker, now time.Time, report *SSMHostPollReport) SSMHostPollResult {
	admit, reason := admitSSMManagedNode(info)
	if !admit {
		report.Aggregates.Excluded++
		return SSMHostPollResult{InstanceID: id, Reason: reason}
	}
	report.Aggregates.Managed++
	pages, rows, denied := pageSSMInventory(ctx, api, id, limits)
	if denied {
		report.Aggregates.DeniedHosts++
		return SSMHostPollResult{InstanceID: id, Outcome: SSMHostInventoryDenied, Reason: ssmCaptureReasonDenied}
	}
	assessment := AssessSSMHostCapture(pages, limits, now)
	report.Aggregates.Pages += len(pages)
	for _, page := range pages {
		report.Aggregates.ResponseBytes += page.PageBytes
	}
	switch assessment.Outcome {
	case SSMHostInventoryStale:
		report.Aggregates.StaleHosts++
		report.Aggregates.Captured++
		return SSMHostPollResult{InstanceID: id, Outcome: SSMHostInventoryStale, Reason: assessment.Reason}
	case SSMHostInventoryPartial:
		report.Aggregates.PartialHosts++
		return SSMHostPollResult{InstanceID: id, Outcome: SSMHostInventoryPartial, Reason: assessment.Reason}
	}
	captureTime := pages[0].CaptureTime
	if tracker.IsRepeat(id, captureTime) {
		report.Aggregates.SuccessfulHosts++
		report.Aggregates.SuppressedHosts++
		report.Aggregates.Captured++
		report.Platforms = append(report.Platforms, ssmPlatformObservation(identity, region, id, *info, now))
		return SSMHostPollResult{InstanceID: id, Outcome: SSMHostInventorySuccessful, Reason: ssmCaptureReasonComplete, Suppressed: true}
	}
	admitted := selectSSMApplicationRows(identity, region, id, pages[0], rows)
	report.Aggregates.Entries += len(admitted)
	report.Aggregates.SuccessfulHosts++
	report.Aggregates.Captured++
	report.Applications = append(report.Applications, admitted...)
	report.Platforms = append(report.Platforms, ssmPlatformObservation(identity, region, id, *info, now))
	tracker.MarkSuperseded(id, captureTime)
	return SSMHostPollResult{InstanceID: id, Outcome: SSMHostInventorySuccessful, Reason: ssmCaptureReasonComplete}
}

// admitSSMManagedNode gates the admitted cohort: online EC2 managed nodes
// only. Anything else is excluded with a visible count, never an empty
// host or a deletion.
func admitSSMManagedNode(info *ssmtypes.InstanceInformation) (bool, string) {
	if info == nil {
		return false, ssmCaptureReasonUnmanaged
	}
	if strings.TrimSpace(string(info.ResourceType)) != string(ssmtypes.ResourceTypeEc2Instance) {
		return false, ssmCaptureReasonNonEC2
	}
	if info.PingStatus != ssmtypes.PingStatusOnline {
		return false, ssmCaptureReasonOffline
	}
	if strings.TrimSpace(aws.ToString(info.InstanceId)) == "" {
		return false, ssmCaptureReasonUnmanaged
	}
	return true, ""
}

// pageSSMInventory reads every AWS:Application page for one host,
// validating the token chain as it goes. It returns the page evidence,
// the raw rows for successful streams only, and whether the read was
// denied. A denial is not a zero inventory result.
func pageSSMInventory(ctx context.Context, api SSMInventoryAPI, id string, limits SSMHostInventoryLimits) ([]SSMInventoryPage, [][]map[string]string, bool) {
	pages := []SSMInventoryPage{}
	rows := [][]map[string]string{}
	var token *string
	for len(pages) < limits.MaxPagesPerHostPerTypePerPoll {
		out, err := api.ListInventoryEntries(ctx, &awsssm.ListInventoryEntriesInput{
			InstanceId: aws.String(id),
			TypeName:   aws.String("AWS:Application"),
			MaxResults: aws.Int32(SSMHostInventoryPageSize),
			NextToken:  token,
		})
		if err != nil {
			if isSSMDenial(err) {
				return nil, nil, true
			}
			// A transient failure is reachable-but-incomplete evidence:
			// the trailing NextToken verdicts truncation below, never an
			// empty host.
			return pages, nil, false
		}
		if strings.TrimSpace(aws.ToString(out.TypeName)) != "AWS:Application" {
			pages = append(pages, SSMInventoryPage{
				InstanceID: id, SourceType: aws.ToString(out.TypeName),
				SchemaVersion: aws.ToString(out.SchemaVersion),
				CaptureTime:   aws.ToString(out.CaptureTime),
				FetchToken:    aws.ToString(token),
			})
			return pages, nil, false
		}
		if strings.TrimSpace(aws.ToString(out.InstanceId)) != "" && strings.TrimSpace(aws.ToString(out.InstanceId)) != id {
			pages = append(pages, SSMInventoryPage{
				InstanceID: aws.ToString(out.InstanceId), SourceType: "AWS:Application",
				SchemaVersion: aws.ToString(out.SchemaVersion),
				CaptureTime:   aws.ToString(out.CaptureTime),
				FetchToken:    aws.ToString(token),
			})
			return pages, nil, false
		}
		pageBytes, maxEntryBytes := weighSSMInventoryPage(out.Entries)
		pages = append(pages, SSMInventoryPage{
			InstanceID: id, SourceType: "AWS:Application",
			SchemaVersion: aws.ToString(out.SchemaVersion),
			CaptureTime:   aws.ToString(out.CaptureTime),
			FetchToken:    aws.ToString(token), NextToken: aws.ToString(out.NextToken),
			EntryCount: len(out.Entries), MaxEntryBytes: maxEntryBytes, PageBytes: pageBytes,
		})
		rows = append(rows, out.Entries)
		if aws.ToString(out.NextToken) == "" {
			return pages, rows, false
		}
		token = out.NextToken
	}
	// The page cap stopped the read with more pages pending: mark the
	// truncation on the evidence so the assessment cannot supersede.
	if len(pages) > 0 {
		pages[len(pages)-1].NextToken = "pending"
	}
	return pages, nil, false
}

// weighSSMInventoryPage accounts one page in compact-JSON bytes: the whole
// entries slice for the page budget, each entry for the per-entry budget.
// These are planning accounts, not wire or heap sizes.
func weighSSMInventoryPage(entries []map[string]string) (pageBytes int64, maxEntryBytes int64) {
	if raw, err := json.Marshal(entries); err == nil {
		pageBytes = int64(len(raw))
	}
	for _, entry := range entries {
		if raw, err := json.Marshal(entry); err == nil && int64(len(raw)) > maxEntryBytes {
			maxEntryBytes = int64(len(raw))
		}
	}
	return pageBytes, maxEntryBytes
}

// selectSSMApplicationRows projects exactly the allowlisted row fields
// from a successful stream. Presence is preserved (a present-but-empty
// value stays a present pointer); non-allowlisted content never leaves
// the response through this projection.
func selectSSMApplicationRows(identity VerifiedIdentity, region, id string, first SSMInventoryPage, rows [][]map[string]string) []collector.SSMHostApplicationObservation {
	admitted := []collector.SSMHostApplicationObservation{}
	seen := map[string]struct{}{}
	for _, page := range rows {
		for _, entry := range page {
			obs := collector.SSMHostApplicationObservation{
				Boundary:      collector.Boundary{AccountID: identity.AccountID, Region: region, ServiceKind: "ssm"},
				Partition:     identity.Partition,
				AccountID:     identity.AccountID,
				Region:        region,
				InstanceID:    id,
				ResourceType:  collector.SSMHostEC2ResourceType,
				SourceType:    collector.SSMHostInventoryTypeApplication,
				SchemaVersion: first.SchemaVersion,
				CaptureTime:   first.CaptureTime,
			}
			applySSMRowFields(&obs, entry)
			key := collector.SSMHostApplicationStableKey(obs)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			admitted = append(admitted, obs)
		}
	}
	return admitted
}

// applySSMRowFields copies exactly the allowlisted keys that are present
// in the entry, trimming values. Non-allowlisted content (URL, Summary,
// hostnames, IPs) never leaves the response through this projection.
func applySSMRowFields(obs *collector.SSMHostApplicationObservation, entry map[string]string) {
	targets := map[string]**string{
		"Name": &obs.Name, "Version": &obs.Version, "Release": &obs.Release,
		"Epoch": &obs.Epoch, "PackageId": &obs.PackageID, "Architecture": &obs.Architecture,
	}
	for _, key := range ssmAllowlistedRowKeys {
		value, present := entry[key]
		if !present {
			continue
		}
		trimmed := strings.TrimSpace(value)
		*targets[key] = &trimmed
	}
}

// ssmPlatformObservation projects the DescribeInstanceInformation platform
// evidence for an admitted host. It carries only its observation time
// with that provenance: the collector never invents a capture time for
// it. Hostnames and IP addresses from the response never enter the
// observation.
func ssmPlatformObservation(identity VerifiedIdentity, region, id string, info ssmtypes.InstanceInformation, now time.Time) collector.SSMHostPlatformObservation {
	obs := collector.SSMHostPlatformObservation{
		Boundary:        collector.Boundary{AccountID: identity.AccountID, Region: region, ServiceKind: "ssm"},
		Partition:       identity.Partition,
		AccountID:       identity.AccountID,
		Region:          region,
		InstanceID:      id,
		ResourceType:    collector.SSMHostEC2ResourceType,
		SourceType:      collector.SSMHostPlatformSourceDescribeInstanceInformation,
		ObservationTime: now.Format(time.RFC3339),
	}
	if platformType := strings.TrimSpace(string(info.PlatformType)); platformType != "" {
		obs.PlatformType = &platformType
	}
	if name := strings.TrimSpace(aws.ToString(info.PlatformName)); name != "" {
		obs.PlatformName = &name
	}
	if version := strings.TrimSpace(aws.ToString(info.PlatformVersion)); version != "" {
		obs.PlatformVersion = &version
	}
	return obs
}

// isSSMDenial reports the authorization failures that make a read denied
// rather than empty: the AccessDenied shapes the QA measurement identity
// received, plus the EC2-style operation denial.
func isSSMDenial(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
		return true
	}
	return false
}
