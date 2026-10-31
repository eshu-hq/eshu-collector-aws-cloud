// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func TestWarningFactIdentityIncludesOperationResourceEffect(t *testing.T) {
	base := WarningObservation{
		Boundary:    Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2", ScopeID: "aws", GenerationID: "g1", CollectorInstanceID: "collector", ClaimToken: "token", ObservedAt: time.Now().UTC()},
		WarningKind: "permission_denied", ErrorClass: "permission_denied", SourceURI: "aws://123456789012/us-east-1",
		Attributes: map[string]any{"operation": "DescribeSecurityGroupRules", "resource": "region:us-east-1", "effect": "security-group-rules-unavailable"},
	}
	first, err := NewWarningFact(base)
	if err != nil {
		t.Fatal(err)
	}
	if first.Kind != AWSKindWarning || first.SourceRef.FactKey != first.StableKey {
		t.Fatalf("warning fact = %+v", first)
	}
	for _, key := range []string{"operation", "resource", "effect"} {
		variant := base
		variant.Attributes = map[string]any{}
		for k, v := range base.Attributes {
			variant.Attributes[k] = v
		}
		variant.Attributes[key] = "different"
		other, err := NewWarningFact(variant)
		if err != nil {
			t.Fatal(err)
		}
		if other.StableKey == first.StableKey {
			t.Fatalf("%s does not affect identity", key)
		}
	}
	result := sdk.Result{State: sdk.ResultPartial, Claim: sdk.Claim{Scope: sdk.Scope{ID: "aws"}, GenerationID: "g1", InstanceID: "collector", FencingToken: "token"}, Generation: sdk.Generation{ID: "g1", ObservedAt: time.Now().UTC()}, Statuses: []sdk.Status{{Class: sdk.StatusWarning, Partial: true}}}
	result, err = AppendLiveWarnings(result, []WarningObservation{base, base}, base.SourceURI, DefaultResourceUse())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Facts) != 1 || result.Statuses[0].WarningCount != 1 || result.Statuses[0].FactCount != 1 {
		t.Fatalf("result = %+v", result)
	}
}

// TestWarningFactPayloadMatchesGolden pins each changed scanner's
// optional-denial input to the emitted aws_warning payload (#9297). A drift
// in the encoded payload fails here before it ever reaches a reducer.
func TestWarningFactPayloadMatchesGolden(t *testing.T) {
	t.Parallel()

	for _, file := range []string{
		"testdata/optional-denial-warning.json",
		"testdata/optional-denial-warning-eks.json",
		"testdata/optional-denial-warning-lambda.json",
		"testdata/optional-denial-warning-s3.json",
	} {
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			checkWarningGolden(t, file)
		})
	}
}

func checkWarningGolden(t *testing.T, file string) {
	t.Helper()

	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Input struct {
			AccountID           string `json:"account_id"`
			Region              string `json:"region"`
			Service             string `json:"service"`
			ScopeID             string `json:"scope_id"`
			GenerationID        string `json:"generation_id"`
			CollectorInstanceID string `json:"collector_instance_id"`
			ClaimToken          string `json:"claim_token"`
			ObservedAt          string `json:"observed_at"`
			WarningKind         string `json:"warning_kind"`
			ErrorClass          string `json:"error_class"`
			Message             string `json:"message"`
			SourceRecordID      string `json:"source_record_id"`
			SourceURI           string `json:"source_uri"`
			Operation           string `json:"operation"`
			Resource            string `json:"resource"`
			Effect              string `json:"effect"`
		} `json:"input"`
		Expected struct {
			Kind           string         `json:"kind"`
			SchemaVersion  string         `json:"schema_version"`
			StableKey      string         `json:"stable_key"`
			SourceRecordID string         `json:"source_record_id"`
			SourceURI      string         `json:"source_uri"`
			Payload        map[string]any `json:"payload"`
		} `json:"expected"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	observedAt, err := time.Parse(time.RFC3339, golden.Input.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := NewWarningFact(WarningObservation{
		Boundary: Boundary{
			AccountID: golden.Input.AccountID, Region: golden.Input.Region,
			ServiceKind: golden.Input.Service, ScopeID: golden.Input.ScopeID,
			GenerationID: golden.Input.GenerationID, CollectorInstanceID: golden.Input.CollectorInstanceID,
			ClaimToken: golden.Input.ClaimToken, ObservedAt: observedAt,
		},
		WarningKind: golden.Input.WarningKind, ErrorClass: golden.Input.ErrorClass,
		Message: golden.Input.Message, SourceRecordID: golden.Input.SourceRecordID,
		SourceURI: golden.Input.SourceURI,
		Attributes: map[string]any{
			"operation": golden.Input.Operation,
			"resource":  golden.Input.Resource, "effect": golden.Input.Effect,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != golden.Expected.Kind || fact.SchemaVersion != golden.Expected.SchemaVersion ||
		fact.StableKey != golden.Expected.StableKey || fact.SourceRef.RecordID != golden.Expected.SourceRecordID ||
		fact.SourceRef.URI != golden.Expected.SourceURI {
		t.Fatalf("warning identity = %+v, want %+v", fact, golden.Expected)
	}
	if !reflect.DeepEqual(fact.Payload, golden.Expected.Payload) {
		got, err := json.Marshal(fact.Payload)
		if err != nil {
			t.Fatal(err)
		}
		want, err := json.Marshal(golden.Expected.Payload)
		if err != nil {
			t.Fatal(err)
		}
		t.Fatalf("warning payload drift:\n got: %s\nwant: %s", got, want)
	}
}

func TestEmptyOptionalDenialEmitsSDKPartialAndTypedWarning(t *testing.T) {
	sourceURI := "aws://123456789012/us-east-1"
	claim := testClaim()
	opts := CollectOptions{ObservedAt: testObservedAt(), SourceURI: sourceURI}
	result, err := CollectPartial(claim, Report{Source: "aws-live:123456789012/us-east-1"}, opts, "ec2/us-east-1: optional rules denied")
	if err != nil {
		t.Fatal(err)
	}
	warning := WarningObservation{
		Boundary:    Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2"},
		WarningKind: "permission_denied", ErrorClass: "permission_denied",
		Attributes: map[string]any{"operation": "DescribeSecurityGroupRules", "resource": "region:us-east-1", "effect": "security-group-rules-unavailable"},
	}
	result, err = AppendLiveWarnings(result, []WarningObservation{warning}, sourceURI, DefaultResourceUse())
	if err != nil {
		t.Fatal(err)
	}
	typed := 0
	for _, fact := range result.Facts {
		if fact.Kind == AWSKindWarning {
			typed++
		}
	}
	if result.State != sdk.ResultPartial || typed != 1 || len(result.Statuses) < 2 || result.Statuses[len(result.Statuses)-1].Class != sdk.StatusWarning || !result.Statuses[len(result.Statuses)-1].Partial {
		t.Fatalf("empty denied SDK result: state=%s typed=%d statuses=%+v", result.State, typed, result.Statuses)
	}
}

// TestAppendLiveWarningsGuardsAndBudgets pins the append guards: a
// non-partial result passes through untouched, zero limits fall back to the
// defaults, an invalid source URI fails, a malformed warning fails, and the
// record and payload budgets fail terminal instead of emitting unbounded
// facts.
func TestAppendLiveWarningsGuardsAndBudgets(t *testing.T) {
	t.Parallel()
	base := WarningObservation{
		Boundary:    Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2", ScopeID: "aws", GenerationID: "g1", CollectorInstanceID: "collector", ClaimToken: "token", ObservedAt: time.Now().UTC()},
		WarningKind: "permission_denied", ErrorClass: "permission_denied", SourceURI: "aws://123456789012/us-east-1",
		Attributes: map[string]any{"operation": "DescribeInstances", "resource": "region:us-east-1", "effect": "instances-unavailable"},
	}
	partial := func() sdk.Result {
		return sdk.Result{State: sdk.ResultPartial, Claim: sdk.Claim{Scope: sdk.Scope{ID: "aws"}, GenerationID: "g1", InstanceID: "collector", FencingToken: "token"}, Generation: sdk.Generation{ID: "g1", ObservedAt: time.Now().UTC()}}
	}

	complete, err := AppendLiveWarnings(sdk.Result{State: sdk.ResultComplete}, []WarningObservation{base}, base.SourceURI, DefaultResourceUse())
	if err != nil {
		t.Fatal(err)
	}
	if len(complete.Facts) != 0 {
		t.Fatalf("non-partial result gained %d facts, want passthrough", len(complete.Facts))
	}

	defaulted, err := AppendLiveWarnings(partial(), []WarningObservation{base}, base.SourceURI, ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if len(defaulted.Facts) != 1 {
		t.Fatalf("zero-limits append facts = %d, want 1 via defaults", len(defaulted.Facts))
	}

	if _, err := AppendLiveWarnings(partial(), []WarningObservation{base}, "https://example.com/collector?token=opaque", DefaultResourceUse()); err == nil {
		t.Fatal("opaque source URI accepted")
	}
	broken := base
	broken.Attributes = map[string]any{}
	if _, err := AppendLiveWarnings(partial(), []WarningObservation{broken}, base.SourceURI, DefaultResourceUse()); err == nil {
		t.Fatal("malformed warning accepted")
	}

	recordCapped := partial()
	recordCapped.Facts = defaulted.Facts
	other := base
	other.Attributes = map[string]any{"operation": "DescribeVolumes", "resource": "region:us-east-1", "effect": "volumes-unavailable"}
	capped, err := AppendLiveWarnings(recordCapped, []WarningObservation{other}, base.SourceURI, ResourceUse{MaxRecordsPerClaim: 1, MaxPayloadBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	if capped.State != sdk.ResultTerminal {
		t.Fatalf("record-budget state = %q, want terminal", capped.State)
	}
	payloadCapped, err := AppendLiveWarnings(partial(), []WarningObservation{base}, base.SourceURI, ResourceUse{MaxRecordsPerClaim: 5000, MaxPayloadBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if payloadCapped.State != sdk.ResultTerminal {
		t.Fatalf("payload-budget state = %q, want terminal", payloadCapped.State)
	}
}
