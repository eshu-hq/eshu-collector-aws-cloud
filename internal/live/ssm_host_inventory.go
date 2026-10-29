// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsssm "github.com/aws/aws-sdk-go-v2/service/ssm"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// SSMInventoryAPI is the bounded SSM surface the host inventory poll
// needs: managed-node discovery plus per-node per-type inventory pages.
// Production wires the SSM client; tests drive fakes. The poll never calls
// GetInventory, associations, or resource-data-sync APIs.
type SSMInventoryAPI interface {
	DescribeInstanceInformation(ctx context.Context, params *awsssm.DescribeInstanceInformationInput, optFns ...func(*awsssm.Options)) (*awsssm.DescribeInstanceInformationOutput, error)
	ListInventoryEntries(ctx context.Context, params *awsssm.ListInventoryEntriesInput, optFns ...func(*awsssm.Options)) (*awsssm.ListInventoryEntriesOutput, error)
}

// NewSSMInventoryClient returns the production SSMInventoryAPI for one
// region-scoped AWS config.
func NewSSMInventoryClient(cfg aws.Config) SSMInventoryAPI {
	return awsssm.NewFromConfig(cfg)
}

// ssmHostDiscoveryMaxPages bounds the filtered DescribeInstanceInformation
// read: the filter names the explicit targets, so more pages than this
// means the discovery stream is incoherent and the poll fails closed.
const ssmHostDiscoveryMaxPages = 10

// Closed assessment reasons. Reasons are static strings: pagination
// tokens, capture times, and instance identities never flow into
// operator-visible text through the verdict path.
const (
	ssmCaptureReasonComplete    = "complete coherent capture within budgets"
	ssmCaptureReasonTruncated   = "pagination stopped with a pending next token"
	ssmCaptureReasonTokenRepeat = "repeating pagination token"
	ssmCaptureReasonTokenChain  = "broken pagination token chain"
	ssmCaptureReasonIncoherent  = "incoherent stream identity or capture time"
	ssmCaptureReasonMissing     = "missing or invalid capture time"
	ssmCaptureReasonNoPages     = "no pages read"
	ssmCaptureReasonEntries     = "entry volume exceeds the per-host capture ceiling"
	ssmCaptureReasonPages       = "page volume exceeds the per-host per-type poll ceiling"
	ssmCaptureReasonEntryBytes  = "entry bytes exceed the per-entry planning budget"
	ssmCaptureReasonPageBytes   = "page bytes exceed the per-page planning budget"
	ssmCaptureReasonStale       = "capture past the stale-age bound"
	ssmCaptureReasonDenied      = "inventory read denied"
	ssmCaptureReasonUnmanaged   = "host not SSM-managed"
	ssmCaptureReasonNonEC2      = "host is not an EC2 managed node"
	ssmCaptureReasonOffline     = "host is not online"
	ssmCaptureReasonDeferred    = "host deferred beyond the per-poll host cap"
)

// SSMInventoryPage is one ListInventoryEntries response for one host and
// inventory type, reduced to the completeness evidence the assessment
// needs. Raw rows, hostnames, and IPs never enter this shape.
type SSMInventoryPage struct {
	// InstanceID is the managed-node instance identifier this page
	// belongs to. Every page in one assessed stream must agree.
	InstanceID string
	// SourceType is the inventory type this page belongs to. Every page
	// in one assessed stream must agree.
	SourceType string
	// SchemaVersion is the inventory schema version this page was read
	// under. Every page in one assessed stream must agree.
	SchemaVersion string
	// CaptureTime is the inventory capture time (RFC 3339) this page
	// reports. Every page in one assessed stream must agree; a missing
	// or invalid capture time makes the stream unknown.
	CaptureTime string
	// FetchToken is the pagination token that fetched this page: empty
	// for the first page, otherwise the previous page's NextToken.
	FetchToken string
	// NextToken is the pagination token for the following page: empty on
	// the final page. A non-empty NextToken on the last assessed page
	// means the read stopped early (truncation).
	NextToken string
	// EntryCount is the number of inventory entries on this page.
	EntryCount int
	// MaxEntryBytes is the largest single entry bytes on this page.
	MaxEntryBytes int64
	// PageBytes is the compact-JSON response bytes of this page.
	PageBytes int64
}

// SSMHostCaptureAssessment is the verdict for one host and inventory type:
// whether the read is complete, whether it may supersede the prior
// generation, the operator outcome, and the static reason. Only a fresh
// complete capture within budgets supersedes; every other verdict
// preserves the prior generation with visible status.
type SSMHostCaptureAssessment struct {
	// Complete reports a fully paginated, coherent, within-budget read.
	Complete bool
	// Supersede reports the read may supersede the prior generation for
	// that host and type. False preserves the prior generation.
	Supersede bool
	// Outcome is the operator verdict: successful, partial, or stale.
	Outcome SSMHostInventoryOutcome
	// Reason is a closed static string naming the verdict class.
	Reason string
}

// AssessSSMHostCapture verdicts one host-and-type inventory read against
// the configured limits at read time now. A complete snapshot needs every
// page (valid nonrepeating pagination tokens), a consistent instance ID,
// type, schema version, and capture time within the stream, volume within
// the ceilings, and a fresh capture — before superseding prior inventory.
// Missing pages, denial-shaped gaps, inconsistent capture times,
// incoherent type pairs, ceiling breaches, and stale captures mean
// partial, stale, or unknown, not an empty host or a deletion.
func AssessSSMHostCapture(pages []SSMInventoryPage, limits SSMHostInventoryLimits, now time.Time) SSMHostCaptureAssessment {
	preserve := func(outcome SSMHostInventoryOutcome, reason string) SSMHostCaptureAssessment {
		return SSMHostCaptureAssessment{Outcome: outcome, Reason: reason}
	}
	if len(pages) == 0 {
		return preserve(SSMHostInventoryPartial, ssmCaptureReasonNoPages)
	}
	first := pages[0]
	if first.CaptureTime == "" {
		return preserve(SSMHostInventoryPartial, ssmCaptureReasonMissing)
	}
	captureTime, err := time.Parse(time.RFC3339, first.CaptureTime)
	if err != nil {
		return preserve(SSMHostInventoryPartial, ssmCaptureReasonMissing)
	}
	if first.FetchToken != "" {
		return preserve(SSMHostInventoryPartial, ssmCaptureReasonTokenChain)
	}
	// seenNextTokens holds the non-empty NextTokens emitted so far. A
	// chained token (page N's NextToken, page N+1's FetchToken) appears
	// twice by construction and is expected; a repeated NextToken means
	// the pager re-emitted a page.
	seenNextTokens := make(map[string]struct{}, len(pages))
	totalEntries := 0
	for i, page := range pages {
		if page.InstanceID != first.InstanceID ||
			page.SourceType != first.SourceType ||
			page.SchemaVersion != first.SchemaVersion ||
			page.CaptureTime != first.CaptureTime {
			return preserve(SSMHostInventoryPartial, ssmCaptureReasonIncoherent)
		}
		if i > 0 && page.FetchToken != pages[i-1].NextToken {
			return preserve(SSMHostInventoryPartial, ssmCaptureReasonTokenChain)
		}
		if page.NextToken != "" {
			if _, seen := seenNextTokens[page.NextToken]; seen {
				return preserve(SSMHostInventoryPartial, ssmCaptureReasonTokenRepeat)
			}
			seenNextTokens[page.NextToken] = struct{}{}
		}
		if page.EntryCount < 0 {
			return preserve(SSMHostInventoryPartial, ssmCaptureReasonIncoherent)
		}
		totalEntries += page.EntryCount
		if page.MaxEntryBytes > int64(limits.MaxEntryBytes) {
			return preserve(SSMHostInventoryPartial, ssmCaptureReasonEntryBytes)
		}
		if page.PageBytes > int64(limits.MaxPageBytes) {
			return preserve(SSMHostInventoryPartial, ssmCaptureReasonPageBytes)
		}
	}
	if last := pages[len(pages)-1]; last.NextToken != "" {
		return preserve(SSMHostInventoryPartial, ssmCaptureReasonTruncated)
	}
	if len(pages) > limits.MaxPagesPerHostPerTypePerPoll {
		return preserve(SSMHostInventoryPartial, ssmCaptureReasonPages)
	}
	if totalEntries > limits.MaxEntriesPerHostPerCapture {
		return preserve(SSMHostInventoryPartial, ssmCaptureReasonEntries)
	}
	if limits.CaptureIsStale(captureTime, now) {
		return preserve(SSMHostInventoryStale, ssmCaptureReasonStale)
	}
	return SSMHostCaptureAssessment{
		Complete:  true,
		Supersede: true,
		Outcome:   SSMHostInventorySuccessful,
		Reason:    ssmCaptureReasonComplete,
	}
}

// SSMCaptureTracker remembers the last superseded capture time per host so
// repeat polls of an unchanged CaptureTime suppress emission instead of
// re-emitting identical observations. It is safe for concurrent polls.
type SSMCaptureTracker struct {
	mu   sync.Mutex
	last map[string]string
}

// NewSSMCaptureTracker returns an empty capture tracker. A scheduled poll
// keeps one tracker across passes; a fresh tracker emits everything once.
func NewSSMCaptureTracker() *SSMCaptureTracker {
	return &SSMCaptureTracker{last: map[string]string{}}
}

// IsRepeat reports whether captureTime equals the last superseded capture
// for the host.
func (t *SSMCaptureTracker) IsRepeat(instanceID, captureTime string) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	last, ok := t.last[instanceID]
	return ok && last == captureTime
}

// MarkSuperseded records captureTime as the last superseded capture for
// the host. It is called only for successful emissions, never for
// partial, stale, or denied reads.
func (t *SSMCaptureTracker) MarkSuperseded(instanceID, captureTime string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.last[instanceID] = captureTime
}

// SSMHostPollResult is the per-host verdict of one inventory poll. Excluded
// hosts (outside the admitted cohort) carry no outcome: they count only in
// the Excluded aggregate.
type SSMHostPollResult struct {
	// InstanceID is the polled managed-node identifier.
	InstanceID string
	// Outcome is the collection verdict; empty for excluded hosts.
	Outcome SSMHostInventoryOutcome
	// Reason is a closed static string naming the verdict class.
	Reason string
	// Suppressed marks a repeat of an already-superseded capture that
	// emitted no new application observations.
	Suppressed bool
}

// SSMHostPollReport is one bounded inventory pass: the admitted
// observations plus the per-host verdicts and aggregate-only telemetry.
// Observations are emitted only for successful (or suppressed-repeat)
// hosts; every other verdict preserves the prior generation.
type SSMHostPollReport struct {
	// Hosts carries one verdict per configured target in sorted order.
	Hosts []SSMHostPollResult
	// Applications carries the admitted allowlisted rows.
	Applications []collector.SSMHostApplicationObservation
	// Platforms carries the fresh platform observations for admitted
	// hosts with a successful or suppressed application read.
	Platforms []collector.SSMHostPlatformObservation
	// Aggregates is the aggregate-only operator telemetry.
	Aggregates SSMHostInventoryAggregates
}

// ssmAllowlistedRowKeys is the exact application allowlist: six fields in
// API casing. URL, Summary, hostnames, and IP addresses never leave the
// response through this set.
var ssmAllowlistedRowKeys = []string{"Name", "Version", "Release", "Epoch", "PackageId", "Architecture"}
