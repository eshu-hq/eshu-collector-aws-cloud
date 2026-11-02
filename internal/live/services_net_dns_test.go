// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// TestSupportedDNSRecordSetMirrorsInTreeFilter locks the live emission
// filter to the in-tree route53 scanner's supportedRecord: alias targets
// always emit, otherwise only A, AAAA, and CNAME (case-insensitive).
func TestSupportedDNSRecordSetMirrorsInTreeFilter(t *testing.T) {
	t.Parallel()

	alias := &route53types.AliasTarget{DNSName: aws.String("target.example.com.")}
	cases := []struct {
		name string
		set  route53types.ResourceRecordSet
		want bool
	}{
		{"A", route53types.ResourceRecordSet{Type: route53types.RRTypeA}, true},
		{"AAAA", route53types.ResourceRecordSet{Type: route53types.RRTypeAaaa}, true},
		{"CNAME", route53types.ResourceRecordSet{Type: route53types.RRTypeCname}, true},
		{"lowercase a", route53types.ResourceRecordSet{Type: route53types.RRType("a")}, true},
		{"alias TXT", route53types.ResourceRecordSet{Type: route53types.RRTypeTxt, AliasTarget: alias}, true},
		{"NS", route53types.ResourceRecordSet{Type: route53types.RRTypeNs}, false},
		{"SOA", route53types.ResourceRecordSet{Type: route53types.RRTypeSoa}, false},
		{"MX", route53types.ResourceRecordSet{Type: route53types.RRTypeMx}, false},
		{"TXT", route53types.ResourceRecordSet{Type: route53types.RRTypeTxt}, false},
		{"SRV", route53types.ResourceRecordSet{Type: route53types.RRTypeSrv}, false},
	}
	for _, tc := range cases {
		if got := supportedDNSRecordSet(tc.set); got != tc.want {
			t.Errorf("supportedDNSRecordSet(%q, alias=%v) = %v, want %v",
				string(tc.set.Type), tc.set.AliasTarget != nil, got, tc.want)
		}
	}
}

// TestDNSRecordObservationMapsSDKRow proves one SDK record set becomes an
// aws_dns_record fact via the builder: the production mapper carries every
// in-tree field (routing policy, alias target, values) and the blank-value
// drop matches the in-tree adapter.
func TestDNSRecordObservationMapsSDKRow(t *testing.T) {
	t.Parallel()

	set := route53types.ResourceRecordSet{
		Name:          aws.String("api.wave1.example.com."),
		Type:          route53types.RRTypeA,
		SetIdentifier: aws.String("w1"),
		TTL:           aws.Int64(300),
		ResourceRecords: []route53types.ResourceRecord{
			{Value: aws.String("192.0.2.10")},
			{Value: aws.String("   ")},
		},
		Weight:        aws.Int64(10),
		HealthCheckId: aws.String("hc-1"),
	}
	zone := route53types.HostedZone{
		Id:     aws.String("/hostedzone/ZWAVE1"),
		Name:   aws.String("wave1.example.com."),
		Config: &route53types.HostedZoneConfig{PrivateZone: false},
	}
	observation, err := dnsRecordObservation(set, zone, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if observation.HostedZoneID != "/hostedzone/ZWAVE1" || observation.RecordName != "api.wave1.example.com." ||
		observation.RecordType != "A" || observation.SetIdentifier != "w1" {
		t.Fatalf("identity = %+v", observation)
	}
	if observation.TTL == nil || *observation.TTL != 300 {
		t.Fatalf("TTL = %+v", observation.TTL)
	}
	if len(observation.Values) != 1 || observation.Values[0] != "192.0.2.10" {
		t.Fatalf("Values = %#v, want blank dropped", observation.Values)
	}
	if observation.RoutingPolicy.Weight == nil || *observation.RoutingPolicy.Weight != 10 || observation.RoutingPolicy.HealthCheckID != "hc-1" {
		t.Fatalf("routing policy = %+v", observation.RoutingPolicy)
	}
	if observation.Boundary.Region != "us-east-1" || observation.Boundary.ServiceKind != "route53" {
		t.Fatalf("boundary = %+v", observation.Boundary)
	}
	if strings.TrimSpace(observation.SourceRecordID) != "" {
		t.Fatalf("SourceRecordID = %q, want empty so the seam applies its in-tree-mirrored default", observation.SourceRecordID)
	}

	fact, err := collector.NewDNSRecordFact(bindDNSObservation(t, *observation))
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != collector.AWSKindDNSRecord {
		t.Fatalf("fact kind = %q, want %q", fact.Kind, collector.AWSKindDNSRecord)
	}
	if fact.Payload["record_type"] != "A" || fact.Payload["normalized_record_name"] != "api.wave1.example.com" {
		t.Fatalf("payload = %#v", fact.Payload)
	}
}

// TestDNSRecordObservationRejectsBlankIdentity proves a supported row that
// cannot produce typed identity fails the read instead of emitting a
// fact-less record that would retire evidence silently.
func TestDNSRecordObservationRejectsBlankIdentity(t *testing.T) {
	t.Parallel()

	zone := route53types.HostedZone{Id: aws.String("/hostedzone/ZWAVE1"), Name: aws.String("wave1.example.com.")}
	if _, err := dnsRecordObservation(route53types.ResourceRecordSet{Type: route53types.RRTypeA}, zone, "us-east-1"); err == nil {
		t.Fatal("blank record name accepted")
	}
	empty := route53types.HostedZone{}
	set := route53types.ResourceRecordSet{Name: aws.String("api.example.com."), Type: route53types.RRTypeA}
	if _, err := dnsRecordObservation(set, empty, "us-east-1"); err == nil {
		t.Fatal("blank hosted zone id accepted")
	}
}

// TestListRoute53AttachesDNSRecordObservations proves the live loader keeps
// its transitional record-set rows while attaching one typed observation
// per supported row: the A row carries it, the NS row does not.
func TestListRoute53AttachesDNSRecordObservations(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/rrset") {
			serveXML(t, `<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets><ResourceRecordSet><Name>example.com.</Name><Type>A</Type><TTL>300</TTL><ResourceRecords><ResourceRecord><Value>192.0.2.10</Value></ResourceRecord></ResourceRecords></ResourceRecordSet><ResourceRecordSet><Name>example.com.</Name><Type>NS</Type><TTL>172800</TTL><ResourceRecords><ResourceRecord><Value>ns-1.awsdns-1.com.</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems></ListResourceRecordSetsResponse>`)(w, r)
			return
		}
		if !strings.Contains(r.URL.Path, "hostedzone") {
			t.Errorf("unexpected Route53 path %q", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		serveXML(t, `<ListHostedZonesResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><HostedZones><HostedZone><Id>/hostedzone/Z123</Id><Name>example.com.</Name><CallerReference>ref</CallerReference><Config><PrivateZone>false</PrivateZone></Config></HostedZone></HostedZones><IsTruncated>false</IsTruncated><Marker></Marker><MaxItems>100</MaxItems></ListHostedZonesResponse>`)(w, r)
	}))

	records, err := listRoute53(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("record count = %d, want 3 (zone, A, NS)", len(records))
	}
	byID := map[string]collector.Record{}
	for _, record := range records {
		byID[record.ID] = record
	}
	aRow := byID["/hostedzone/Z123/example.com./A"]
	if aRow.DNSRecord == nil {
		t.Fatal("A record set carries no typed DNS observation")
	}
	if aRow.DNSRecord.RecordName != "example.com." || aRow.DNSRecord.RecordType != "A" ||
		len(aRow.DNSRecord.Values) != 1 || aRow.DNSRecord.Values[0] != "192.0.2.10" {
		t.Fatalf("A observation = %+v", aRow.DNSRecord)
	}
	if got := byID["/hostedzone/Z123/example.com./NS"]; got.DNSRecord != nil {
		t.Fatalf("NS record set carries a typed observation: %+v", got.DNSRecord)
	}
}

// TestCollectReportFansOutDNSRecords proves typed DNS rows flow through
// CollectReport into the Outcome slice with the claim account stamped.
func TestCollectReportFansOutDNSRecords(t *testing.T) {
	t.Parallel()

	reader := Collector{
		LoadConfig: func(context.Context, string) (aws.Config, error) {
			return aws.Config{Region: "us-east-1"}, nil
		},
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{"route53": func(_ context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
			return []collector.Record{{
				DNSRecord: &collector.DNSRecordObservation{
					Boundary:     collector.Boundary{Region: "us-east-1", ServiceKind: "route53"},
					HostedZoneID: "/hostedzone/Z123", RecordName: "example.com.", RecordType: "A",
				},
			}}, nil
		}},
	}
	outcome, err := reader.CollectReport(context.Background(), Config{
		AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"route53"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.DNSRecords) != 1 || outcome.DNSRecords[0].Boundary.AccountID != "123456789012" {
		t.Fatalf("DNSRecords = %+v", outcome.DNSRecords)
	}
}

// TestAppendOutcomeFactsEmitsDNSRecords proves the shared production
// sequence emits validated aws_dns_record facts: dropping the DNS appender
// fails here instead of silently emitting zero DNS facts in production.
func TestAppendOutcomeFactsEmitsDNSRecords(t *testing.T) {
	t.Parallel()

	outcome := Outcome{
		DNSRecords: []collector.DNSRecordObservation{{
			Boundary:     collector.Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "route53"},
			HostedZoneID: "/hostedzone/Z123", RecordName: "example.com.", RecordType: "A",
		}},
	}
	observedAt := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	result := sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultComplete,
		Claim: sdk.Claim{
			ComponentID: collector.ComponentID, InstanceID: "aws-parity-dns",
			CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem,
			Scope:       sdk.Scope{ID: "aws:123456789012:us-east-1", Kind: "component"},
			SourceRunID: "dns-parity-run", GenerationID: "aws:123456789012:us-east-1:dns:1",
			WorkItemID: "dns-parity-work", FencingToken: "dns-parity-token",
			Attempt: 1, Deadline: observedAt.Add(time.Hour), ConfigHandle: "component-config:aws-cloud",
		},
		Generation: sdk.Generation{ID: "aws:123456789012:us-east-1:dns:1", ObservedAt: observedAt},
	}
	var err error
	if result, err = AppendOutcomeFacts(result, outcome, "aws:route53:us-east-1:dns-parity", collector.DefaultResourceUse()); err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.NewValidator(collector.Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected pipeline result carrying DNS facts: %v", err)
	}
	found := false
	for _, fact := range result.Facts {
		if fact.Kind == collector.AWSKindDNSRecord {
			found = true
		}
	}
	if !found {
		t.Fatalf("pipeline result missing %q (facts = %d)", collector.AWSKindDNSRecord, len(result.Facts))
	}
}

func bindDNSObservation(t *testing.T, observation collector.DNSRecordObservation) collector.DNSRecordObservation {
	t.Helper()
	observation.Boundary.AccountID = "123456789012"
	observation.Boundary.ScopeID = "aws:123456789012:us-east-1"
	observation.Boundary.GenerationID = "aws:123456789012:us-east-1:dns:1"
	observation.Boundary.CollectorInstanceID = "aws-parity-dns"
	observation.Boundary.ClaimToken = "dns-parity-token"
	observation.Boundary.ObservedAt = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	observation.SourceURI = "aws:route53:us-east-1:dns-parity"
	return observation
}
