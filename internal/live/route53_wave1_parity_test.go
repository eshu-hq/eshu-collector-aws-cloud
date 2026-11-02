// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-sdk/factschema"
)

// TestWave1Route53ParityAgainstInTreeOracle locks live DNS emission to the
// in-tree oracle keys: every aws_dns_record fact the in-tree Scanner.Scan
// derives for the shared fixture (testdata/wave1-route53-parity.json) has a
// satellite twin with the identical stable key. Oracle keys come from the
// in-tree scan; the re-derivation recipe is in
// testdata/stable-key-provenance.md, the vendored oracle output is
// testdata/wave1-route53-oracle.txt, and
// TestWave1Route53OracleOutputMatchesFrozenKeys pins the 7 lines below to
// it. The hosted-zone resource envelope is out of scope: the satellite keeps
// the zone as a transitional record while the in-tree scan emits a resource
// fact from a different identity, so only the 6 DNS keys are asserted here.
func TestWave1Route53ParityAgainstInTreeOracle(t *testing.T) {
	t.Parallel()

	fixture := loadWave1Route53Fixture(t)
	zone := wave1Route53SDKZone(fixture.HostedZone)

	got := map[string]string{}
	skipped := 0
	for _, row := range fixture.RecordSets {
		set := wave1Route53SDKSet(row)
		if !supportedDNSRecordSet(set) {
			skipped++
			continue
		}
		observation, err := dnsRecordObservation(set, zone, "us-east-1")
		if err != nil {
			t.Fatal(err)
		}
		observation.Boundary = wave1Boundary("123456789012", "us-east-1", "route53")
		observation.SourceURI = "aws:route53:us-east-1:wave1-parity"
		fact, err := collector.NewDNSRecordFact(*observation)
		if err != nil {
			t.Fatal(err)
		}
		got[fact.Kind+"\x00"+fact.StableKey] = row.Name + "#" + row.Type
	}
	if skipped != 4 {
		t.Fatalf("filtered row count = %d, want 4 (NS, SOA, MX, TXT)", skipped)
	}

	want := []string{
		"aws_dns_record\x005c04a10b2f648315742f148c3a7e491fed16fb950e482f6ead1f83794ab309cb",
		"aws_dns_record\x00f7e7608a0814cb20b905af0ddc81489181b275b9c22cd1ad39cd97628c31ef3d",
		"aws_dns_record\x00c5678b2bbb19bc0c96c0aec59f0a0b0b033524ddec7873fecf09e649df3f8f33",
		"aws_dns_record\x008e4d4814bd3c2112cc3bd816dbde60565903ede371da7ceecca87e2e3f885037",
		"aws_dns_record\x006d429f36aa188a60cac370c204432bde292165dc4f0a21f544d12c7b8985d9ba",
		"aws_dns_record\x00f6e0a0482f39f7513a95e3b6d0b813da90432b13eb01c8b62c260d52b930f77c",
	}
	if len(got) != len(want) {
		t.Fatalf("parity fact count = %d, want %d", len(got), len(want))
	}
	for _, key := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("missing oracle fact %q", key)
		}
	}

	// The alias row's non-key fields must survive the bridge too: the
	// target identity and health flag are the fields the seam cannot
	// re-derive from the key.
	alias := wave1Route53Fact(t, fixture, "wave1.example.com.", "A")
	decoded, err := factschema.DecodeAWSDNSRecord(factschema.Envelope{
		FactKind: alias.Kind, SchemaVersion: alias.SchemaVersion, Payload: alias.Payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decoded.AliasTarget == nil || decoded.AliasTarget.DNSName != "dualstack.wave1-123.us-east-1.elb.amazonaws.com." ||
		decoded.AliasTarget.HostedZoneID != "Z35SXDOTRQ7X7K" || !decoded.AliasTarget.EvaluateTargetHealth {
		t.Fatalf("alias target = %+v", decoded.AliasTarget)
	}
	geo := wave1Route53Fact(t, fixture, "cdn.wave1.example.com.", "CNAME")
	decodedGeo, err := factschema.DecodeAWSDNSRecord(factschema.Envelope{
		FactKind: geo.Kind, SchemaVersion: geo.SchemaVersion, Payload: geo.Payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decodedGeo.RoutingPolicy == nil || decodedGeo.RoutingPolicy.GeoLocation == nil ||
		decodedGeo.RoutingPolicy.GeoLocation.CountryCode == nil ||
		*decodedGeo.RoutingPolicy.GeoLocation.CountryCode != "US" {
		t.Fatalf("geo routing = %+v", decodedGeo.RoutingPolicy)
	}
	v6 := wave1Route53Fact(t, fixture, "v6.wave1.example.com.", "AAAA")
	decodedV6, err := factschema.DecodeAWSDNSRecord(factschema.Envelope{
		FactKind: v6.Kind, SchemaVersion: v6.SchemaVersion, Payload: v6.Payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decodedV6.RoutingPolicy == nil || decodedV6.RoutingPolicy.Region == nil ||
		*decodedV6.RoutingPolicy.Region != "us-east-1" || decodedV6.RoutingPolicy.Failover == nil ||
		*decodedV6.RoutingPolicy.Failover != "PRIMARY" {
		t.Fatalf("latency/failover routing = %+v", decodedV6.RoutingPolicy)
	}
	cidr := wave1Route53Fact(t, fixture, "cidr.wave1.example.com.", "A")
	decodedCIDR, err := factschema.DecodeAWSDNSRecord(factschema.Envelope{
		FactKind: cidr.Kind, SchemaVersion: cidr.SchemaVersion, Payload: cidr.Payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decodedCIDR.RoutingPolicy == nil || decodedCIDR.RoutingPolicy.CIDRCollectionID == nil ||
		*decodedCIDR.RoutingPolicy.CIDRCollectionID != "cidr-1" ||
		decodedCIDR.RoutingPolicy.CIDRLocationName == nil ||
		*decodedCIDR.RoutingPolicy.CIDRLocationName != "loc-a" ||
		decodedCIDR.RoutingPolicy.TrafficPolicyInstanceID == nil ||
		*decodedCIDR.RoutingPolicy.TrafficPolicyInstanceID != "tpi-1" {
		t.Fatalf("CIDR routing = %+v", decodedCIDR.RoutingPolicy)
	}
	multi := wave1Route53Fact(t, fixture, "multi.wave1.example.com.", "A")
	decodedMulti, err := factschema.DecodeAWSDNSRecord(factschema.Envelope{
		FactKind: multi.Kind, SchemaVersion: multi.SchemaVersion, Payload: multi.Payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decodedMulti.RoutingPolicy == nil || decodedMulti.RoutingPolicy.MultiValueAnswer == nil ||
		!*decodedMulti.RoutingPolicy.MultiValueAnswer || len(decodedMulti.Values) != 2 {
		t.Fatalf("multivalue routing = %+v values=%#v", decodedMulti.RoutingPolicy, decodedMulti.Values)
	}
}

// TestWave1Route53OracleOutputMatchesFrozenKeys pins the frozen satellite
// key list to the vendored in-tree oracle output: every kind+key line in
// testdata/wave1-route53-oracle.txt must appear exactly once in the parity
// test's 6 DNS keys plus the zone resource key frozen here, and vice versa.
// The two sides are independent transcriptions of two separate oracle runs,
// so a transcription drift on either side fails here instead of passing
// silently.
func TestWave1Route53OracleOutputMatchesFrozenKeys(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "wave1-route53-oracle.txt"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		index, kind, key, err := splitOracleLine(line)
		if err != nil {
			t.Fatalf("unparsable oracle line %q: %v", line, err)
		}
		if index != count {
			t.Fatalf("oracle line %d out of order: %q", count, line)
		}
		entry := kind + "\x00" + key
		if !wave1Route53OracleFrozenSet[entry] {
			t.Errorf("oracle fact %q matches no frozen satellite key", entry)
		}
		seen[entry] = true
		count++
	}
	if count != len(wave1Route53OracleFrozenKeys) {
		t.Fatalf("oracle entry count = %d, want %d", count, len(wave1Route53OracleFrozenKeys))
	}
	for _, key := range wave1Route53OracleFrozenKeys {
		if !seen[key] {
			t.Errorf("frozen satellite key %q matches no oracle fact", key)
		}
	}
}

// wave1Route53OracleFrozenKeys is the union of the frozen DNS list in
// TestWave1Route53ParityAgainstInTreeOracle (6 record keys) and the zone
// resource key (frozen here; out of satellite scope), transcribed so this
// test cross-checks both against the vendored oracle output instead of
// trusting either transcription alone.
var wave1Route53OracleFrozenKeys = []string{ // Frozen parity vectors: test data.
	"aws_resource\x00767795649e31f526d373dae899fa2c66e7cd20b36f3bf66cba92daf4802ca300",
	"aws_dns_record\x005c04a10b2f648315742f148c3a7e491fed16fb950e482f6ead1f83794ab309cb",
	"aws_dns_record\x00f7e7608a0814cb20b905af0ddc81489181b275b9c22cd1ad39cd97628c31ef3d",
	"aws_dns_record\x00c5678b2bbb19bc0c96c0aec59f0a0b0b033524ddec7873fecf09e649df3f8f33",
	"aws_dns_record\x008e4d4814bd3c2112cc3bd816dbde60565903ede371da7ceecca87e2e3f885037",
	"aws_dns_record\x006d429f36aa188a60cac370c204432bde292165dc4f0a21f544d12c7b8985d9ba",
	"aws_dns_record\x00f6e0a0482f39f7513a95e3b6d0b813da90432b13eb01c8b62c260d52b930f77c",
}

var wave1Route53OracleFrozenSet = func() map[string]bool { // Derived once from the frozen vectors above.
	set := make(map[string]bool, len(wave1Route53OracleFrozenKeys))
	for _, key := range wave1Route53OracleFrozenKeys {
		set[key] = true
	}
	return set
}()

// wave1Route53Fixture mirrors the in-tree post-mapper scanner types
// (go/internal/collector/awscloud/service/route53/types.go) using those
// exact Go field names, so the fixture unmarshals on both sides.
type wave1Route53Fixture struct {
	ScopeID             string                  `json:"scope_id"`
	GenerationID        string                  `json:"generation_id"`
	CollectorInstanceID string                  `json:"collector_instance_id"`
	HostedZone          wave1Route53HostedZone  `json:"hosted_zone"`
	RecordSets          []wave1Route53RecordSet `json:"record_sets"`
}

type wave1Route53HostedZone struct {
	ID                     string `json:"ID"`
	Name                   string `json:"Name"`
	CallerReference        string `json:"CallerReference"`
	Comment                string `json:"Comment"`
	Private                bool   `json:"Private"`
	ResourceRecordSetCount int64  `json:"ResourceRecordSetCount"`
}

type wave1Route53AliasTarget struct {
	DNSName              string `json:"DNSName"`
	HostedZoneID         string `json:"HostedZoneID"`
	EvaluateTargetHealth bool   `json:"EvaluateTargetHealth"`
}

type wave1Route53GeoLocation struct {
	ContinentCode   string `json:"ContinentCode"`
	CountryCode     string `json:"CountryCode"`
	SubdivisionCode string `json:"SubdivisionCode"`
}

type wave1Route53CIDRRouting struct {
	CollectionID string `json:"CollectionID"`
	LocationName string `json:"LocationName"`
}

type wave1Route53RecordSet struct {
	Name                    string                   `json:"Name"`
	Type                    string                   `json:"Type"`
	SetIdentifier           string                   `json:"SetIdentifier"`
	TTL                     *int64                   `json:"TTL"`
	Values                  []string                 `json:"Values"`
	AliasTarget             *wave1Route53AliasTarget `json:"AliasTarget"`
	Weight                  *int64                   `json:"Weight"`
	Region                  string                   `json:"Region"`
	Failover                string                   `json:"Failover"`
	HealthCheckID           string                   `json:"HealthCheckID"`
	MultiValueAnswer        *bool                    `json:"MultiValueAnswer"`
	TrafficPolicyInstanceID string                   `json:"TrafficPolicyInstanceID"`
	GeoLocation             *wave1Route53GeoLocation `json:"GeoLocation"`
	CIDRRouting             *wave1Route53CIDRRouting `json:"CIDRRouting"`
}

func loadWave1Route53Fixture(t *testing.T) wave1Route53Fixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "wave1-route53-parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture wave1Route53Fixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

// wave1Route53SDKZone bridges the fixture zone into the AWS SDK input the
// production dnsRecordObservation mapper reads.
func wave1Route53SDKZone(zone wave1Route53HostedZone) route53types.HostedZone {
	return route53types.HostedZone{
		Id:                     aws.String(zone.ID),
		Name:                   aws.String(zone.Name),
		CallerReference:        aws.String(zone.CallerReference),
		Config:                 &route53types.HostedZoneConfig{Comment: aws.String(zone.Comment), PrivateZone: zone.Private},
		ResourceRecordSetCount: aws.Int64(zone.ResourceRecordSetCount),
	}
}

// wave1Route53SDKSet bridges one fixture row into the AWS SDK input the
// production mapper reads, mirroring the in-tree awssdk.mapper field for
// field: trimmed strings pass through, absent sections stay nil.
func wave1Route53SDKSet(row wave1Route53RecordSet) route53types.ResourceRecordSet {
	set := route53types.ResourceRecordSet{
		Name:                    aws.String(row.Name),
		Type:                    route53types.RRType(row.Type),
		SetIdentifier:           aws.String(row.SetIdentifier),
		TTL:                     row.TTL,
		Weight:                  row.Weight,
		Region:                  route53types.ResourceRecordSetRegion(row.Region),
		Failover:                route53types.ResourceRecordSetFailover(row.Failover),
		HealthCheckId:           aws.String(row.HealthCheckID),
		MultiValueAnswer:        row.MultiValueAnswer,
		TrafficPolicyInstanceId: aws.String(row.TrafficPolicyInstanceID),
	}
	for _, value := range row.Values {
		set.ResourceRecords = append(set.ResourceRecords, route53types.ResourceRecord{Value: aws.String(value)})
	}
	if row.AliasTarget != nil {
		set.AliasTarget = &route53types.AliasTarget{
			DNSName:              aws.String(row.AliasTarget.DNSName),
			HostedZoneId:         aws.String(row.AliasTarget.HostedZoneID),
			EvaluateTargetHealth: row.AliasTarget.EvaluateTargetHealth,
		}
	}
	if row.GeoLocation != nil {
		set.GeoLocation = &route53types.GeoLocation{
			ContinentCode:   aws.String(row.GeoLocation.ContinentCode),
			CountryCode:     aws.String(row.GeoLocation.CountryCode),
			SubdivisionCode: aws.String(row.GeoLocation.SubdivisionCode),
		}
	}
	if row.CIDRRouting != nil {
		set.CidrRoutingConfig = &route53types.CidrRoutingConfig{
			CollectionId: aws.String(row.CIDRRouting.CollectionID),
			LocationName: aws.String(row.CIDRRouting.LocationName),
		}
	}
	return set
}

// wave1Route53Fact rebuilds one fixture row's fact through the production
// path for payload assertions the key comparison cannot see.
func wave1Route53Fact(t *testing.T, fixture wave1Route53Fixture, name, recordType string) factView {
	t.Helper()
	zone := wave1Route53SDKZone(fixture.HostedZone)
	for _, row := range fixture.RecordSets {
		if row.Name != name || row.Type != recordType {
			continue
		}
		observation, err := dnsRecordObservation(wave1Route53SDKSet(row), zone, "us-east-1")
		if err != nil {
			t.Fatal(err)
		}
		observation.Boundary = wave1Boundary("123456789012", "us-east-1", "route53")
		observation.SourceURI = "aws:route53:us-east-1:wave1-parity"
		fact, err := collector.NewDNSRecordFact(*observation)
		if err != nil {
			t.Fatal(err)
		}
		return factView{Kind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload}
	}
	t.Fatalf("fixture row %s %s not found", name, recordType)
	return factView{}
}

type factView struct {
	Kind          string
	SchemaVersion string
	Payload       map[string]any
}
