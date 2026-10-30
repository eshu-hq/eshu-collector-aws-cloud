// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestListAPIGatewayListsRestAndHTTPAPIs(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/restapis"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items": [{"id": "a1b2c3", "name": "orders-api"}]}`))
		case strings.HasSuffix(path, "/domainnames") && !strings.Contains(path, "/v2/"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items": [{"domainName": "api.example.com"}]}`))
		case strings.HasSuffix(path, "/v2/apis"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Items": [{"ApiId": "h1", "Name": "orders-http"}]}`))
		case strings.HasSuffix(path, "/v2/domainnames"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Items": [{"DomainName": "http.example.com", "DomainNameArn": "arn:aws:apigateway:us-east-1::/domainnames/http.example.com"}]}`))
		default:
			t.Errorf("unexpected API Gateway path %q", path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	records, err := listAPIGateway(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 {
		t.Fatalf("record count = %d, want 4 (rest, domain, http, v2 domain)", len(records))
	}
	want := map[string]string{
		"a1b2c3": "orders-api",
		"h1":     "orders-http",
	}
	for _, record := range records {
		if name, ok := want[record.ID]; ok && record.Name != name {
			t.Errorf("API record %q name = %q, want %q", record.ID, record.Name, name)
		}
	}
}

func TestListAPIGatewayRestError(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))

	if _, err := listAPIGateway(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "apigateway get rest APIs") {
		t.Fatalf("err = %v, want apigateway get rest APIs failure", err)
	}
}

func TestListCloudFrontListsDistributions(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "distribution") {
			t.Errorf("unexpected CloudFront path %q", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<DistributionList xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Marker></Marker><MaxItems>100</MaxItems><IsTruncated>false</IsTruncated><Quantity>2</Quantity><Items><DistributionSummary><Id>E123</Id><ARN>arn:aws:cloudfront::123456789012:distribution/E123</ARN><DomainName>d123.cloudfront.net</DomainName><Status>Deployed</Status></DistributionSummary><DistributionSummary><Id>E456</Id><ARN>arn:aws:cloudfront::123456789012:distribution/E456</ARN><Status>Deployed</Status></DistributionSummary></Items></DistributionList>`))
	}))

	records, err := listCloudFront(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("record count = %d, want 2", len(records))
	}
	if records[0].Name != "d123.cloudfront.net" {
		t.Errorf("first distribution name = %q, want domain name", records[0].Name)
	}
	if records[1].Name != "E456" {
		t.Errorf("second distribution name = %q, want id fallback", records[1].Name)
	}
}

func TestListCloudWatchLogsListsGroups(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.Header.Get("X-Amz-Target"), "DescribeLogGroups") {
			t.Errorf("unexpected Logs target %q", r.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		serveJSON(t, `{"logGroups": [{"logGroupName": "/app/orders", "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/app/orders"}]}`)(w, r)
	}))

	records, err := listCloudWatchLogs(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1", len(records))
	}
	if records[0].Name != "/app/orders" || records[0].Detail != "service=cloudwatchlogs region=us-east-1 kind=log-group" {
		t.Fatalf("log group record = %#v", records[0])
	}
}

func TestListEventBridgeListsBusesAndRules(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch target := r.Header.Get("X-Amz-Target"); {
		case strings.HasSuffix(target, "ListEventBuses"):
			serveJSON(t, `{"EventBuses": [{"Name": "default", "Arn": "arn:aws:events:us-east-1:123456789012:event-bus/default"}]}`)(w, r)
		case strings.HasSuffix(target, "ListRules"):
			serveJSON(t, `{"Rules": [{"Name": "hourly", "Arn": "arn:aws:events:us-east-1:123456789012:rule/default/hourly"}]}`)(w, r)
		default:
			t.Errorf("unexpected EventBridge target %q", target)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	records, err := listEventBridge(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("record count = %d, want 2 (bus, rule)", len(records))
	}
	if records[0].Name != "default" || records[1].Name != "hourly" {
		t.Fatalf("eventbridge records = %#v", records)
	}
}

func TestListRoute53ListsZonesAndRecordSets(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		if strings.HasSuffix(r.URL.Path, "/rrset") {
			_, _ = w.Write([]byte(`<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets><ResourceRecordSet><Name>example.com.</Name><Type>A</Type><TTL>300</TTL></ResourceRecordSet></ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems></ListResourceRecordSetsResponse>`))
			return
		}
		if !strings.Contains(r.URL.Path, "hostedzone") {
			t.Errorf("unexpected Route53 path %q", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`<ListHostedZonesResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><HostedZones><HostedZone><Id>/hostedzone/Z123</Id><Name>example.com.</Name><CallerReference>ref</CallerReference></HostedZone></HostedZones><IsTruncated>false</IsTruncated><Marker></Marker><MaxItems>100</MaxItems></ListHostedZonesResponse>`))
	}))

	records, err := listRoute53(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("record count = %d, want 2 (zone, record set)", len(records))
	}
	if records[0].Name != "example.com" || records[0].Detail != "service=route53 region=us-east-1 kind=hosted-zone" {
		t.Fatalf("zone record = %#v", records[0])
	}
	if records[1].ID != "/hostedzone/Z123/example.com./A" || records[1].Name != "example.com" {
		t.Fatalf("record-set record = %#v", records[1])
	}
}
