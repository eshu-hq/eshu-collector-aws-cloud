// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func ssmHostTestBoundary() Boundary {
	return Boundary{
		AccountID: "000000000001", Region: "us-east-1", ServiceKind: "ssm",
		ScopeID: "scope-1", GenerationID: "gen-1", CollectorInstanceID: "collector-1",
		FencingToken: 7, ObservedAt: time.Date(2026, 10, 29, 22, 33, 2, 0, time.UTC),
	}
}

func ssmHostTestApplication() SSMHostApplicationObservation {
	str := func(s string) *string { return &s }
	return SSMHostApplicationObservation{
		Boundary:       ssmHostTestBoundary(),
		Partition:      "aws",
		AccountID:      "000000000001",
		Region:         "us-east-1",
		InstanceID:     "i-00000000000000001",
		ResourceType:   "AWS::EC2::Instance",
		SourceType:     "AWS:Application",
		SchemaVersion:  "1.0.0",
		CaptureTime:    "2026-10-29T22:31:19Z",
		Name:           str("example-agent"),
		Version:        str("1.0.0"),
		Release:        str("1.example"),
		Epoch:          str("0"),
		PackageID:      str("example-agent-1.0.0-1.example.x86_64"),
		Architecture:   str("x86_64"),
		SourceURI:      "aws://000000000001",
		SourceRecordID: "i-00000000000000001#app#0",
	}
}

func TestSSMHostApplicationStableKeyMatchesContract(t *testing.T) {
	t.Parallel()
	obs := ssmHostTestApplication()
	key := SSMHostApplicationStableKey(obs)
	// Canonical row order is the #9556 struct order: name, version, release,
	// epoch, package_id, architecture.
	raw := `{"name":"example-agent","version":"1.0.0","release":"1.example","epoch":"0","package_id":"example-agent-1.0.0-1.example.x86_64","architecture":"x86_64"}`
	sum := sha256.Sum256([]byte(raw))
	want := "aws_ssm_host_application/aws/000000000001/us-east-1/i-00000000000000001/2026-10-29T22:31:19Z/" + hex.EncodeToString(sum[:])
	if key != want {
		t.Fatalf("stable key = %q, want %q", key, want)
	}
}

func TestSSMHostApplicationKeyIdentity(t *testing.T) {
	t.Parallel()
	base := ssmHostTestApplication()
	if got := SSMHostApplicationStableKey(base); got != SSMHostApplicationStableKey(ssmHostTestApplication()) {
		t.Fatal("identical rows in one capture must share a stable key")
	}
	blank := ""
	nilRow := base
	nilRow.Name, nilRow.Version, nilRow.Release = nil, nil, nil
	nilRow.Epoch, nilRow.PackageID, nilRow.Architecture = nil, nil, nil
	emptyRow := base
	emptyRow.Name, emptyRow.Version, emptyRow.Release = &blank, &blank, &blank
	emptyRow.Epoch, emptyRow.PackageID, emptyRow.Architecture = &blank, &blank, &blank
	if SSMHostApplicationStableKey(nilRow) != SSMHostApplicationStableKey(emptyRow) {
		t.Fatal("absent and present-but-empty row fields must hash identically")
	}
	other := base
	other.CaptureTime = "2026-10-30T22:31:19Z"
	if SSMHostApplicationStableKey(other) == SSMHostApplicationStableKey(base) {
		t.Fatal("another capture must be a new observation, not a duplicate")
	}
	padded := base
	deref := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	pad := func(s string) *string { v := "  " + s + "\t"; return &v }
	padded.Name, padded.Version, padded.Release = pad(deref(base.Name)), pad(deref(base.Version)), pad(deref(base.Release))
	padded.Epoch, padded.PackageID, padded.Architecture = pad(deref(base.Epoch)), pad(deref(base.PackageID)), pad(deref(base.Architecture))
	padded.Partition, padded.Region, padded.InstanceID, padded.CaptureTime = "  "+base.Partition+" ", " "+base.Region, base.InstanceID+"\t", " "+base.CaptureTime+"  "
	if SSMHostApplicationStableKey(padded) != SSMHostApplicationStableKey(base) {
		t.Fatal("whitespace-padded fields must share the trimmed stable key")
	}
}

func TestNewSSMHostApplicationFact(t *testing.T) {
	t.Parallel()
	fact, err := NewSSMHostApplicationFact(ssmHostTestApplication())
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindSSMHostApplication || fact.SchemaVersion != "1.0.0" ||
		fact.SourceConfidence != sdk.SourceConfidenceReported {
		t.Fatalf("fact identity changed: %#v", fact)
	}
	if fact.StableKey != SSMHostApplicationStableKey(ssmHostTestApplication()) {
		t.Fatalf("stable key = %q", fact.StableKey)
	}
	if fact.SourceRef.URI != "aws://000000000001" || fact.SourceRef.RecordID != "i-00000000000000001#app#0" {
		t.Fatalf("provenance changed: %#v", fact.SourceRef)
	}
	for key, want := range map[string]any{
		"partition": "aws", "account_id": "000000000001", "region": "us-east-1",
		"instance_id": "i-00000000000000001", "resource_type": "AWS::EC2::Instance",
		"source_type": "AWS:Application", "schema_version": "1.0.0",
		"capture_time": "2026-10-29T22:31:19Z", "name": "example-agent",
		"version": "1.0.0", "release": "1.example", "epoch": "0",
		"package_id": "example-agent-1.0.0-1.example.x86_64", "architecture": "x86_64",
		"collector_instance_id": "collector-1",
	} {
		if fact.Payload[key] != want {
			t.Fatalf("payload[%q] = %v, want %v", key, fact.Payload[key], want)
		}
	}
	for _, forbidden := range []string{"url", "summary", "hostname", "computer_name", "ip_address", "ipaddress"} {
		if _, ok := fact.Payload[forbidden]; ok {
			t.Fatalf("payload carries excluded key %q", forbidden)
		}
	}
	if err := sdk.ValidateShareSafeKeys(fact.Payload); err != nil {
		t.Fatalf("share-safe check failed: %v", err)
	}
}

func TestNewSSMHostApplicationFactRejects(t *testing.T) {
	t.Parallel()
	base := ssmHostTestApplication()
	cases := []struct {
		name   string
		mutate func(*SSMHostApplicationObservation)
	}{
		{"missing capture", func(o *SSMHostApplicationObservation) { o.CaptureTime = "" }},
		{"invalid capture", func(o *SSMHostApplicationObservation) { o.CaptureTime = "not-a-time" }},
		{"wrong source type", func(o *SSMHostApplicationObservation) { o.SourceType = "AWS:File" }},
		{"empty source type", func(o *SSMHostApplicationObservation) { o.SourceType = "" }},
		{"non-ec2 resource", func(o *SSMHostApplicationObservation) { o.ResourceType = "AWS::SSM::ManagedInstance" }},
		{"empty instance", func(o *SSMHostApplicationObservation) { o.InstanceID = "  " }},
		{"missing account", func(o *SSMHostApplicationObservation) { o.Boundary.AccountID = "" }},
		{"missing uri", func(o *SSMHostApplicationObservation) { o.SourceURI = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			obs := base
			tc.mutate(&obs)
			if _, err := NewSSMHostApplicationFact(obs); err == nil {
				t.Fatalf("observation was accepted: %#v", obs)
			}
		})
	}
}

func TestNewSSMHostPlatformFact(t *testing.T) {
	t.Parallel()
	obsTime := "2026-10-29T22:33:02Z"
	str := func(s string) *string { return &s }
	mk := func(source, capture string) SSMHostPlatformObservation {
		obs := SSMHostPlatformObservation{
			Boundary:        ssmHostTestBoundary(),
			Partition:       "aws",
			AccountID:       "000000000001",
			Region:          "us-east-1",
			InstanceID:      "i-00000000000000001",
			ResourceType:    "AWS::EC2::Instance",
			PlatformType:    str("Linux"),
			PlatformName:    str("ExampleLinux"),
			PlatformVersion: str("1.0"),
			SourceType:      source,
			ObservationTime: obsTime,
			SourceURI:       "aws://000000000001",
		}
		if capture != "" {
			obs.CaptureTime = &capture
		}
		return obs
	}
	inventory, err := NewSSMHostPlatformFact(mk("ssm_inventory", "2026-10-29T22:31:19Z"))
	if err != nil {
		t.Fatalf("inventory platform rejected: %v", err)
	}
	if inventory.Kind != AWSKindSSMHostPlatform || inventory.Payload["capture_time"] != "2026-10-29T22:31:19Z" {
		t.Fatalf("inventory platform payload changed: %#v", inventory.Payload)
	}
	dii, err := NewSSMHostPlatformFact(mk("describe_instance_information", ""))
	if err != nil {
		t.Fatalf("DII platform rejected: %v", err)
	}
	if _, ok := dii.Payload["capture_time"]; ok {
		t.Fatalf("DII observation carries an invented capture time: %#v", dii.Payload)
	}
	if dii.Payload["observation_time"] != obsTime {
		t.Fatalf("DII observation time missing: %#v", dii.Payload)
	}
	if SSMHostPlatformStableKey(mk("ssm_inventory", "2026-10-29T22:31:19Z")) !=
		"aws_ssm_host_platform/aws/000000000001/us-east-1/i-00000000000000001/ssm_inventory" {
		t.Fatal("platform stable key shape changed")
	}
	rejects := map[string]SSMHostPlatformObservation{
		"dii with capture time":     mk("describe_instance_information", "2026-10-29T22:31:19Z"),
		"inventory without capture": mk("ssm_inventory", ""),
		"unknown provenance":        mk("custom", "2026-10-29T22:31:19Z"),
		"missing observation time": func() SSMHostPlatformObservation {
			o := mk("ssm_inventory", "2026-10-29T22:31:19Z")
			o.ObservationTime = ""
			return o
		}(),
		"invalid observation time": func() SSMHostPlatformObservation {
			o := mk("ssm_inventory", "2026-10-29T22:31:19Z")
			o.ObservationTime = "yesterday"
			return o
		}(),
	}
	for name, obs := range rejects {
		if _, err := NewSSMHostPlatformFact(obs); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestValidateSSMHostPlatformProvenance mirrors the #9556 pairing check:
// a DescribeInstanceInformation observation carrying a capture time is
// rejected, while both valid pairings pass.
func TestValidateSSMHostPlatformProvenance(t *testing.T) {
	t.Parallel()
	if err := ValidateSSMHostPlatformProvenance("describe_instance_information", true); err == nil {
		t.Fatal("DII with capture time: error = nil, want rejection")
	}
	if err := ValidateSSMHostPlatformProvenance("describe_instance_information", false); err != nil {
		t.Fatalf("DII without capture time: error = %v, want nil", err)
	}
	if err := ValidateSSMHostPlatformProvenance("ssm_inventory", true); err != nil {
		t.Fatalf("inventory with capture time: error = %v, want nil", err)
	}
	if err := ValidateSSMHostPlatformProvenance("ssm_inventory", false); err == nil {
		t.Fatal("inventory without capture time: error = nil, want rejection")
	}
}

func TestAppendLiveSSMHostInventory(t *testing.T) {
	t.Parallel()
	claim := testClaim()
	base := mustCollect(t, "complete.json", claim, testObservedAt(), "")
	obs := ssmHostTestApplication()
	obs.Boundary = Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ssm"}
	result, err := AppendLiveSSMHostApplications(base, []SSMHostApplicationObservation{obs, obs}, "aws://123456789012", ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Facts) != len(base.Facts)+1 {
		t.Fatalf("facts = %d, want %d (identical rows deduplicate)", len(result.Facts), len(base.Facts)+1)
	}
	fact := result.Facts[len(result.Facts)-1]
	if fact.Kind != AWSKindSSMHostApplication || fact.SourceRef.ScopeID != claim.Scope.ID {
		t.Fatalf("application fact is not claim-bound: %#v", fact.SourceRef)
	}
	if strings.Contains(fact.SourceRef.URI, claim.FencingToken) {
		t.Fatalf("fencing token leaked into provenance URI %q", fact.SourceRef.URI)
	}
	bounded, err := AppendLiveSSMHostApplications(base, []SSMHostApplicationObservation{obs}, "aws://123456789012", ResourceUse{
		MaxRecordsPerClaim: len(base.Facts), MaxPayloadBytes: 65536,
	})
	if err != nil || bounded.State != sdk.ResultTerminal || len(bounded.Facts) != 0 {
		t.Fatalf("bounded result = %#v, error = %v, want terminal without facts", bounded, err)
	}
	unchanged := base
	unchanged.State = sdk.ResultUnchanged
	if kept, err := AppendLiveSSMHostApplications(unchanged, []SSMHostApplicationObservation{obs}, "aws://123456789012", ResourceUse{}); err != nil || len(kept.Facts) != len(base.Facts) {
		t.Fatalf("unchanged claim gained facts: %#v, error = %v", kept, err)
	}
}
