// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	"github.com/eshu-hq/eshu-sdk/factschema"
)

// frozenDNSRecordKey is the in-tree stable key for the shared-fixture DNS
// record (go/internal/collector/awscloud/source_parity_8852_test.go,
// parity8852DNSRecordKey). The satellite seam must reproduce it byte for
// byte from the same fixture section. Re-derivation recipe (oracle commit,
// command, fixture hash): testdata/stable-key-provenance.md.
const frozenDNSRecordKey = "5bd39ab9188007203e5eed1bd57eac7bfcc6cfb8ee5a86b6cdea2a64e09983e6"

type dnsParityFixture struct {
	ScopeID             string `json:"scope_id"`
	GenerationID        string `json:"generation_id"`
	CollectorInstanceID string `json:"collector_instance_id"`
	DNSRecord           struct {
		HostedZoneID      string   `json:"hosted_zone_id"`
		HostedZoneName    string   `json:"hosted_zone_name"`
		HostedZonePrivate bool     `json:"hosted_zone_private"`
		RecordName        string   `json:"record_name"`
		RecordType        string   `json:"record_type"`
		TTL               *int64   `json:"ttl"`
		Values            []string `json:"values"`
		AliasTarget       struct {
			DNSName              string `json:"dns_name"`
			HostedZoneID         string `json:"hosted_zone_id"`
			EvaluateTargetHealth bool   `json:"evaluate_target_health"`
		} `json:"alias_target"`
		RoutingPolicy struct {
			HealthCheckID string `json:"health_check_id"`
		} `json:"routing_policy"`
	} `json:"dns_record"`
}

func loadDNSParityFixture(t *testing.T) dnsParityFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/8852-parity-awscloud.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture dnsParityFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func dnsParityObservation(t *testing.T) DNSRecordObservation {
	t.Helper()
	fixture := loadDNSParityFixture(t)
	in := fixture.DNSRecord
	return DNSRecordObservation{
		Boundary: Boundary{
			AccountID: "123456789012", Region: "us-east-1", ServiceKind: catalog.ServiceRoute53,
			ScopeID: fixture.ScopeID, GenerationID: fixture.GenerationID,
			CollectorInstanceID: fixture.CollectorInstanceID, FencingToken: 7,
			ObservedAt: time.Date(2026, 10, 20, 13, 0, 0, 0, time.UTC),
		},
		HostedZoneID:      in.HostedZoneID,
		HostedZoneName:    in.HostedZoneName,
		HostedZonePrivate: in.HostedZonePrivate,
		RecordName:        in.RecordName,
		RecordType:        in.RecordType,
		TTL:               in.TTL,
		Values:            in.Values,
		AliasTarget: &DNSAliasTarget{
			DNSName:              in.AliasTarget.DNSName,
			HostedZoneID:         in.AliasTarget.HostedZoneID,
			EvaluateTargetHealth: in.AliasTarget.EvaluateTargetHealth,
		},
		RoutingPolicy: DNSRoutingPolicy{
			HealthCheckID: in.RoutingPolicy.HealthCheckID,
		},
		SourceURI:      "aws:route53:record/api.parity.example.com",
		SourceRecordID: "dns-row-1",
	}
}

func TestDNSRecordFactSharedFixtureParity(t *testing.T) {
	t.Parallel()

	fact, err := NewDNSRecordFact(dnsParityObservation(t))
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindDNSRecord || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.StableKey != frozenDNSRecordKey {
		t.Fatalf("StableKey = %q, want in-tree frozen %q", fact.StableKey, frozenDNSRecordKey)
	}
	if fact.SourceConfidence != "reported" {
		t.Fatalf("confidence = %q, want reported", fact.SourceConfidence)
	}
	if got, want := fact.Payload["record_type"], "A"; got != want {
		t.Fatalf("record_type = %#v, want %#v (normalized)", got, want)
	}
	if got, want := fact.Payload["normalized_record_name"], "api.parity.example.com"; got != want {
		t.Fatalf("normalized_record_name = %#v, want %#v", got, want)
	}
	decoded, err := factschema.DecodeAWSDNSRecord(factschema.Envelope{
		FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload,
	})
	if err != nil || decoded.RecordName != "api.parity.example.com." {
		t.Fatalf("typed decode = %+v, %v", decoded, err)
	}
}

func TestDNSRecordFactRejectsHostileInput(t *testing.T) {
	t.Parallel()

	observation := dnsParityObservation(t)
	observation.HostedZoneID = "   "
	if _, err := NewDNSRecordFact(observation); err == nil {
		t.Fatal("blank hosted_zone_id accepted")
	}
	observation = dnsParityObservation(t)
	observation.RecordName = "   "
	if _, err := NewDNSRecordFact(observation); err == nil {
		t.Fatal("blank record_name accepted")
	}
	observation = dnsParityObservation(t)
	observation.RecordType = "   "
	if _, err := NewDNSRecordFact(observation); err == nil {
		t.Fatal("blank record_type accepted")
	}
	observation = dnsParityObservation(t)
	observation.Boundary.AccountID = ""
	if _, err := NewDNSRecordFact(observation); err == nil {
		t.Fatal("blank account_id accepted")
	}
	observation = dnsParityObservation(t)
	observation.SourceURI = "https://example.com/collector?token=opaque"
	if _, err := NewDNSRecordFact(observation); err == nil {
		t.Fatal("opaque source URI accepted")
	}
}

// TestDNSRecordSourceIDJoinsParts pins the deterministic source record id:
// zone, type, and normalized name always join, with the weighted-set
// identifier appended only when present.
func TestDNSRecordSourceIDJoinsParts(t *testing.T) {
	t.Parallel()
	if got := dnsRecordSourceID("Z123", "Example.COM.", "A", ""); got != "Z123#A#example.com" {
		t.Fatalf("dnsRecordSourceID() = %q", got)
	}
	if got := dnsRecordSourceID("Z123", "Example.COM.", "A", "w1"); got != "Z123#A#example.com#w1" {
		t.Fatalf("dnsRecordSourceID(weighted) = %q", got)
	}
}
