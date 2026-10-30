// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"fmt"
	"testing"
	"time"
)

// ssmCoherentPages builds a complete dated multi-page stream: 27 pages of
// 48 rows like the measured populated host, with a valid token chain.
func ssmCoherentPages(capture string) []SSMInventoryPage {
	pages := make([]SSMInventoryPage, 0, 27)
	for i := 0; i < 27; i++ {
		fetch := ""
		if i > 0 {
			fetch = fmt.Sprintf("page-%d", i)
		}
		next := ""
		if i < 26 {
			next = fmt.Sprintf("page-%d", i+1)
		}
		pages = append(pages, SSMInventoryPage{
			InstanceID: "i-00000000000000001", SourceType: "AWS:Application",
			SchemaVersion: "1.0", CaptureTime: capture,
			FetchToken: fetch, NextToken: next,
			EntryCount: 48, MaxEntryBytes: 459, PageBytes: 22 * 1024,
		})
	}
	return pages
}

func TestAssessSSMHostCapture(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	fresh := now.Add(-2 * time.Minute).Format(time.RFC3339)
	limits := ssmTestLimits()
	complete := AssessSSMHostCapture(ssmCoherentPages(fresh), limits, now)
	if !complete.Complete || !complete.Supersede || complete.Outcome != SSMHostInventorySuccessful {
		t.Fatalf("27-page coherent capture rejected: %+v", complete)
	}
	mutate := func(pages []SSMInventoryPage, fn func(*SSMInventoryPage)) []SSMInventoryPage {
		out := make([]SSMInventoryPage, len(pages))
		copy(out, pages)
		fn(&out[len(out)-1])
		return out
	}
	cases := []struct {
		name    string
		pages   []SSMInventoryPage
		outcome SSMHostInventoryOutcome
	}{
		{"no pages", nil, SSMHostInventoryPartial},
		{"page-1 truncation", ssmCoherentPages(fresh)[:1], SSMHostInventoryPartial},
		{"token repeat", func() []SSMInventoryPage {
			pages := ssmCoherentPages(fresh)
			pages[2].FetchToken = "page-1"
			pages[1].NextToken = "page-1"
			return pages[:3]
		}(), SSMHostInventoryPartial},
		{"chain break", func() []SSMInventoryPage {
			pages := ssmCoherentPages(fresh)
			pages[5].FetchToken = "page-999"
			return pages[:6]
		}(), SSMHostInventoryPartial},
		{"split capture", func() []SSMInventoryPage {
			pages := ssmCoherentPages(fresh)
			pages[10].CaptureTime = now.Add(-time.Hour).Format(time.RFC3339)
			return pages[:11]
		}(), SSMHostInventoryPartial},
		{"mixed types", func() []SSMInventoryPage {
			pages := ssmCoherentPages(fresh)
			pages[3].SourceType = "AWS:File"
			return pages[:4]
		}(), SSMHostInventoryPartial},
		{"undated", mutate(ssmCoherentPages(""), func(p *SSMInventoryPage) {}), SSMHostInventoryPartial},
		{"invalid capture", func() []SSMInventoryPage {
			pages := ssmCoherentPages("not-a-time")
			return pages
		}(), SSMHostInventoryPartial},
		{"entry ceiling", func() []SSMInventoryPage {
			pages := ssmCoherentPages(fresh)
			pages[0].EntryCount = 5001
			pages[0].NextToken = ""
			return pages[:1]
		}(), SSMHostInventoryPartial},
		{"page ceiling", func() []SSMInventoryPage {
			pages := ssmCoherentPages(fresh)
			many := make([]SSMInventoryPage, 0, 101)
			for i := 0; i < 101; i++ {
				page := pages[i%len(pages)]
				if i > 0 {
					page.FetchToken = fmt.Sprintf("chain-%d", i-1)
				} else {
					page.FetchToken = ""
				}
				page.NextToken = fmt.Sprintf("chain-%d", i)
				page.EntryCount = 1
				many = append(many, page)
			}
			many[len(many)-1].NextToken = ""
			return many
		}(), SSMHostInventoryPartial},
		{"entry bytes", mutate(ssmCoherentPages(fresh)[:1], func(p *SSMInventoryPage) {
			p.MaxEntryBytes = 1025
			p.NextToken = ""
		}), SSMHostInventoryPartial},
		{"page bytes", mutate(ssmCoherentPages(fresh)[:1], func(p *SSMInventoryPage) {
			p.PageBytes = 50*1024 + 1
			p.NextToken = ""
		}), SSMHostInventoryPartial},
		{"stale", ssmCoherentPages(now.Add(-3 * time.Hour).Format(time.RFC3339)), SSMHostInventoryStale},
		{"non-allowlisted type", func() []SSMInventoryPage {
			pages := ssmCoherentPages(fresh)
			for i := range pages {
				pages[i].SourceType = "AWS:File"
			}
			return pages
		}(), SSMHostInventoryPartial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := AssessSSMHostCapture(tc.pages, limits, now)
			if got.Outcome != tc.outcome {
				t.Fatalf("outcome = %q (%s), want %q", got.Outcome, got.Reason, tc.outcome)
			}
			if got.Supersede {
				t.Fatalf("non-success verdict supersedes: %+v", got)
			}
			if tc.name == "entry ceiling" && got.Reason != ssmCaptureReasonEntries {
				t.Fatalf("entry ceiling reason = %q", got.Reason)
			}
			if tc.name == "page ceiling" && got.Reason != ssmCaptureReasonPages {
				t.Fatalf("page ceiling reason = %q", got.Reason)
			}
			if tc.name == "non-allowlisted type" && got.Reason != ssmCaptureReasonSourceNotAllowlisted {
				t.Fatalf("non-allowlisted type reason = %q, want the allowlist verdict", got.Reason)
			}
			if got.Reason == "" {
				t.Fatal("verdict carries no reason")
			}
		})
	}
}
