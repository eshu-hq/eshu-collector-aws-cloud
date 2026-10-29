// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"
	"testing"
	"time"
)

// ssmTestLimits is one coherent deployment configuration: a 1h capture
// interval with the recommended 2-interval stale bound, a 30m cross-type
// skew, and resource values within the arbiter ceilings.
func ssmTestLimits() SSMHostInventoryLimits {
	return SSMHostInventoryLimits{
		MaxHostsPerPoll:               10,
		MaxPagesPerHostPerTypePerPoll: 100,
		MaxEntriesPerHostPerCapture:   5000,
		MaxEntryBytes:                 1024,
		MaxPageBytes:                  50 * 1024,
		CaptureInterval:               time.Hour,
		MaxCaptureAge:                 2 * time.Hour,
		MaxCrossTypeSkew:              30 * time.Minute,
		MaxPlatformObservationAge:     time.Hour,
		RetentionDays:                 30,
		Targets:                       []string{"i-00000000000000001"},
	}
}

func TestSSMHostInventoryLimitsValidate(t *testing.T) {
	t.Parallel()
	if err := ssmTestLimits().Validate(); err != nil {
		t.Fatalf("coherent limits rejected: %v", err)
	}
	coherent := ssmTestLimits()
	cases := []struct {
		name   string
		mutate func(*SSMHostInventoryLimits)
	}{
		{"no hosts", func(l *SSMHostInventoryLimits) { l.MaxHostsPerPoll = 0 }},
		{"no pages", func(l *SSMHostInventoryLimits) { l.MaxPagesPerHostPerTypePerPoll = 0 }},
		{"pages above ceiling", func(l *SSMHostInventoryLimits) { l.MaxPagesPerHostPerTypePerPoll = 101 }},
		{"no entries", func(l *SSMHostInventoryLimits) { l.MaxEntriesPerHostPerCapture = 0 }},
		{"entries above ceiling", func(l *SSMHostInventoryLimits) { l.MaxEntriesPerHostPerCapture = 5001 }},
		{"no entry bytes", func(l *SSMHostInventoryLimits) { l.MaxEntryBytes = 0 }},
		{"entry bytes above ceiling", func(l *SSMHostInventoryLimits) { l.MaxEntryBytes = 1025 }},
		{"no page bytes", func(l *SSMHostInventoryLimits) { l.MaxPageBytes = 0 }},
		{"page bytes above ceiling", func(l *SSMHostInventoryLimits) { l.MaxPageBytes = 50*1024 + 1 }},
		{"no interval", func(l *SSMHostInventoryLimits) { l.CaptureInterval = 0 }},
		{"no capture age", func(l *SSMHostInventoryLimits) { l.MaxCaptureAge = 0 }},
		{"age below interval", func(l *SSMHostInventoryLimits) { l.MaxCaptureAge = 30 * time.Minute }},
		{"no skew", func(l *SSMHostInventoryLimits) { l.MaxCrossTypeSkew = 0 }},
		{"skew above age", func(l *SSMHostInventoryLimits) { l.MaxCrossTypeSkew = 3 * time.Hour }},
		{"no platform age", func(l *SSMHostInventoryLimits) { l.MaxPlatformObservationAge = 0 }},
		{"no retention", func(l *SSMHostInventoryLimits) { l.RetentionDays = 0 }},
		{"no targets", func(l *SSMHostInventoryLimits) { l.Targets = nil }},
		{"blank target", func(l *SSMHostInventoryLimits) { l.Targets = []string{"  "} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			limits := coherent
			tc.mutate(&limits)
			if err := limits.Validate(); err == nil {
				t.Fatal("invalid limits were accepted")
			}
		})
	}
}

func TestSSMHostInventoryFreshness(t *testing.T) {
	t.Parallel()
	limits := ssmTestLimits()
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	fresh := now.Add(-90 * time.Minute)
	if limits.CaptureIsStale(fresh, now) {
		t.Fatal("90-minute capture reads stale under a 2h bound")
	}
	if !limits.CaptureIsStale(now.Add(-121*time.Minute), now) {
		t.Fatal("121-minute capture reads fresh under a 2h bound")
	}
	app := now.Add(-10 * time.Minute)
	if !limits.CrossTypeSkewOK(app, app.Add(29*time.Minute)) || limits.CrossTypeSkewOK(app, app.Add(31*time.Minute)) {
		t.Fatal("cross-type skew bound misapplied at 30m")
	}
	if !limits.PlatformObservationIsFresh(now.Add(-59*time.Minute), now) ||
		limits.PlatformObservationIsFresh(now.Add(-61*time.Minute), now) {
		t.Fatal("platform observation rule misapplied at 1h")
	}
}

func TestSSMHostInventoryAggregatesLogFields(t *testing.T) {
	t.Parallel()
	fields := (SSMHostInventoryAggregates{
		Targets: 2, Managed: 2, Captured: 2, SuccessfulHosts: 2,
		Entries: 2605, Pages: 53, ResponseBytes: 1195978, Outcome: SSMHostInventorySuccessful,
	}).LogFields()
	keys := []string{
		"targets", "managed", "captured", "excluded",
		"denied_hosts", "partial_hosts", "stale_hosts", "successful_hosts",
		"suppressed_hosts", "entries", "pages", "response_bytes", "outcome",
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			t.Fatalf("telemetry field %q missing", key)
		}
	}
	for key, value := range fields {
		text, ok := value.(string)
		if !ok {
			continue
		}
		if key != "outcome" {
			t.Fatalf("string telemetry value under %q", key)
		}
		_ = text
	}
	joined := ""
	for key := range fields {
		joined += key + ";"
	}
	for _, leak := range []string{"i-", "example-agent", "192.168", "https://"} {
		if strings.Contains(joined, leak) {
			t.Fatalf("telemetry field names leak content %q", leak)
		}
	}
	if len(fields) != 13 {
		t.Fatalf("telemetry carries %d fields, want exactly the 13 count fields", len(fields))
	}
}
