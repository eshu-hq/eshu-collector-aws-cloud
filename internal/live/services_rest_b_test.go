// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"strings"
	"testing"
)

func apigatewayResponses() map[string]string {
	return map[string]string{
		"GET /restapis":       `{"item":[{"id":"a1","name":"api"}]}`,
		"GET /domainnames":    `{"item":[{"domainName":"d.example.com","domainNameArn":"arn:apigateway:d"}]}`,
		"GET /v2/apis":        `{"items":[{"apiId":"h1","name":"h"}]}`,
		"GET /v2/domainnames": `{"items":[{"domainName":"h.example.com","domainNameArn":"arn:apigateway:h"}]}`,
	}
}

func TestListAPIGatewayReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	cfg := stubServer(t, restStub(t, apigatewayResponses(), nil))

	records, err := listAPIGateway(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listAPIGateway error = %v", err)
	}
	want := map[string]string{
		"a1": "api",
		// REST domain names carry no ARN, so the record falls back to the
		// stable service/region/name triple; HTTP domain names carry one.
		"apigateway/us-east-1/d.example.com": "d.example.com",
		"h1":                                 "h",
		"arn:apigateway:h":                   "h.example.com",
	}
	if len(records) != len(want) {
		t.Fatalf("len(records) = %d, want %d (%v)", len(records), len(want), records)
	}
	for _, record := range records {
		if want[record.ID] != record.Name {
			t.Errorf("record %q name = %q, want %q", record.ID, record.Name, want[record.ID])
		}
	}

	for _, tc := range []struct{ prefix, wrap string }{
		{"/restapis", "apigateway get rest APIs"},
		{"/domainnames", "apigateway get domain names"},
		{"/v2/apis", "apigatewayv2 get APIs"},
		{"/v2/domainnames", "apigatewayv2 get domain names"},
	} {
		cfg := stubServer(t, restStub(t, apigatewayResponses(), map[string]bool{tc.prefix: true}))
		if _, err := listAPIGateway(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.wrap) {
			t.Errorf("%s: error = %v, want %q", tc.prefix, err, tc.wrap)
		}
	}
}

func TestListS3ReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	responses := map[string]string{
		"GET /": `<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
			`<Owner><ID>owner</ID></Owner>` +
			`<Buckets><Bucket><Name>b1</Name><CreationDate>2026-01-01T00:00:00Z</CreationDate></Bucket></Buckets>` +
			`</ListAllMyBucketsResult>`,
	}
	cfg := stubServer(t, restStub(t, responses, nil))

	records, err := listS3(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listS3 error = %v", err)
	}
	if len(records) != 1 || records[0].ID != "arn:aws:s3:::b1" || records[0].Name != "b1" {
		t.Fatalf("records = %v, want the stubbed bucket", records)
	}

	cfg = stubServer(t, restStub(t, responses, map[string]bool{"/": true}))
	if _, err := listS3(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "s3 list buckets") {
		t.Fatalf("denied ListBuckets: error = %v, want s3 list buckets", err)
	}
}

func TestListCloudFrontReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	responses := map[string]string{
		"GET /2020-05-31/distribution": `<DistributionList xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/">` +
			`<Marker></Marker><MaxItems>100</MaxItems><IsTruncated>false</IsTruncated><Quantity>1</Quantity>` +
			`<Items><DistributionSummary><Id>d1</Id><ARN>arn:aws:cloudfront::1:distribution/d1</ARN><DomainName>d.cloudfront.net</DomainName></DistributionSummary></Items>` +
			`</DistributionList>`,
	}
	cfg := stubServer(t, restStub(t, responses, nil))

	records, err := listCloudFront(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listCloudFront error = %v", err)
	}
	if len(records) != 1 || records[0].ID != "arn:aws:cloudfront::1:distribution/d1" || records[0].Name != "d.cloudfront.net" {
		t.Fatalf("records = %v, want the stubbed distribution", records)
	}

	cfg = stubServer(t, restStub(t, responses, map[string]bool{"/2020-05-31/distribution": true}))
	if _, err := listCloudFront(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "cloudfront list distributions") {
		t.Fatalf("denied ListDistributions: error = %v, want cloudfront list distributions", err)
	}
}

func route53Responses() map[string]string {
	xmlns := "https://route53.amazonaws.com/doc/2013-04-01/"
	return map[string]string{
		"GET /2013-04-01/hostedzone": `<ListHostedZonesResponse xmlns="` + xmlns + `">` +
			`<HostedZones><HostedZone><Id>Z1</Id><Name>example.com.</Name></HostedZone></HostedZones>` +
			`<IsTruncated>false</IsTruncated><Marker></Marker><MaxItems>100</MaxItems>` +
			`</ListHostedZonesResponse>`,
		"GET /2013-04-01/hostedzone/Z1/rrset": `<ListResourceRecordSetsResponse xmlns="` + xmlns + `">` +
			`<ResourceRecordSets><ResourceRecordSet><Name>example.com.</Name><Type>A</Type></ResourceRecordSet></ResourceRecordSets>` +
			`<IsTruncated>false</IsTruncated>` +
			`</ListResourceRecordSetsResponse>`,
	}
}

func TestListRoute53ReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	cfg := stubServer(t, restStub(t, route53Responses(), nil))

	records, err := listRoute53(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listRoute53 error = %v", err)
	}
	want := map[string]string{
		"Z1":                "example.com",
		"Z1/example.com./A": "example.com",
	}
	if len(records) != len(want) {
		t.Fatalf("len(records) = %d, want %d (%v)", len(records), len(want), records)
	}
	for _, record := range records {
		if want[record.ID] != record.Name {
			t.Errorf("record %q name = %q, want %q", record.ID, record.Name, want[record.ID])
		}
	}

	for _, tc := range []struct{ prefix, wrap string }{
		{"/2013-04-01/hostedzone", "route53 list hosted zones"},
		{"/2013-04-01/hostedzone/Z1/rrset", "route53 list resource record sets"},
	} {
		cfg := stubServer(t, restStub(t, route53Responses(), map[string]bool{tc.prefix: true}))
		if _, err := listRoute53(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.wrap) {
			t.Errorf("%s: error = %v, want %q", tc.prefix, err, tc.wrap)
		}
	}
}
