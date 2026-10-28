// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// stubConfig points every SDK client built from it at the httptest server:
// NewFromConfig honors Config.BaseEndpoint, so the production listXXX
// functions run unmodified against canned responses. Static dummy
// credentials keep the signer off the ambient chain; the stub ignores auth.
func stubConfig(server *httptest.Server) aws.Config {
	return aws.Config{
		Region:       "us-east-1",
		Credentials:  aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "TOKEN")),
		BaseEndpoint: aws.String(server.URL),
	}
}

// stubWriter reports stub-side write failures through the test: handler
// errors are otherwise invisible, and the repo errcheck set (check-blank)
// requires every error handled.
type stubWriter struct {
	t *testing.T
	w http.ResponseWriter
}

func (s stubWriter) xml(body string) {
	s.t.Helper()
	s.w.Header().Set("Content-Type", "text/xml")
	if _, err := s.w.Write([]byte(body)); err != nil {
		s.t.Errorf("stub write xml: %v", err)
	}
}

func (s stubWriter) json(body string) {
	s.t.Helper()
	s.w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	if _, err := s.w.Write([]byte(body)); err != nil {
		s.t.Errorf("stub write json: %v", err)
	}
}

func (s stubWriter) raw(contentType, body string) {
	s.t.Helper()
	s.w.Header().Set("Content-Type", contentType)
	if _, err := s.w.Write([]byte(body)); err != nil {
		s.t.Errorf("stub write: %v", err)
	}
}

// queryStub dispatches AWS Query-protocol actions (EC2, RDS, ELBV2, IAM, SNS,
// SQS) to canned envelopes keyed by the Action form parameter. Actions in
// fail return a 400 AccessDenied envelope so error branches run without the
// SDK retrying: client errors are not retried.
func queryStub(t *testing.T, responses map[string]string, fail map[string]bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := stubWriter{t: t, w: w}
		if err := r.ParseForm(); err != nil {
			t.Errorf("stub parse form: %v", err)
		}
		action := r.FormValue("Action")
		if fail[action] {
			w.WriteHeader(http.StatusBadRequest)
			out.xml(`<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>denied</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
			return
		}
		if body, ok := responses[action]; ok {
			out.xml(body)
			return
		}
		http.Error(w, "unknown Action "+action, http.StatusBadRequest)
	})
}

// jsonStub dispatches AWS JSON-protocol operations (DynamoDB, ECR, ECS, SSM,
// SecretsManager, CloudWatchLogs, EventBridge) by the X-Amz-Target header.
// Targets in fail return a 400 modeled fault; DynamoDB endpoint discovery is
// answered with an empty set so the configured stub endpoint stays in use.
func jsonStub(t *testing.T, responses map[string]string, fail map[string]bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := stubWriter{t: t, w: w}
		target := r.Header.Get("X-Amz-Target")
		if strings.HasSuffix(target, "DescribeEndpoints") {
			out.json(`{"Endpoints":[]}`)
			return
		}
		if fail[target] {
			w.WriteHeader(http.StatusBadRequest)
			out.json(`{"__type":"AccessDeniedException","message":"denied"}`)
			return
		}
		if body, ok := responses[target]; ok {
			out.json(body)
			return
		}
		http.Error(w, "unknown Target "+target, http.StatusBadRequest)
	})
}

// restStub dispatches REST-protocol operations (Lambda, EKS, APIGateway, S3,
// CloudFront, Route53) by method plus path prefix. Paths in fail return a
// 400 fault.
func restStub(t *testing.T, responses map[string]string, fail map[string]bool) http.Handler {
	t.Helper()
	routes := make([]string, 0, len(responses))
	for route := range responses {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool { return len(routes[i]) > len(routes[j]) })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := stubWriter{t: t, w: w}
		for _, route := range routes {
			body := responses[route]
			method, prefix, _ := strings.Cut(route, " ")
			if r.Method != method || !strings.HasPrefix(r.URL.Path, prefix) {
				continue
			}
			if fail[prefix] {
				w.WriteHeader(http.StatusBadRequest)
				out.raw("application/json", `{"message":"denied"}`)
				return
			}
			if trimmed := strings.TrimSpace(body); strings.HasPrefix(trimmed, "<") {
				out.xml(body)
			} else {
				out.raw("application/json", body)
			}
			return
		}
		http.Error(w, "unknown route "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
	})
}

// stubServer starts a stub endpoint and returns the config that targets it.
func stubServer(t *testing.T, handler http.Handler) aws.Config {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return stubConfig(server)
}

func ec2Responses() map[string]string {
	ec2NS := "http://ec2.amazonaws.com/doc/2016-11-15/"
	return map[string]string{
		"DescribeVpcs":               `<DescribeVpcsResponse xmlns="` + ec2NS + `"><requestId>r</requestId><vpcSet><item><vpcId>vpc-1</vpcId><tagSet><item><key>Name</key><value>main</value></item></tagSet></item></vpcSet></DescribeVpcsResponse>`,
		"DescribeSubnets":            `<DescribeSubnetsResponse xmlns="` + ec2NS + `"><requestId>r</requestId><subnetSet><item><subnetId>subnet-1</subnetId></item></subnetSet></DescribeSubnetsResponse>`,
		"DescribeSecurityGroups":     `<DescribeSecurityGroupsResponse xmlns="` + ec2NS + `"><requestId>r</requestId><securityGroupInfo><item><groupId>sg-1</groupId><groupName>web</groupName></item></securityGroupInfo></DescribeSecurityGroupsResponse>`,
		"DescribeSecurityGroupRules": `<DescribeSecurityGroupRulesResponse xmlns="` + ec2NS + `"><requestId>r</requestId><securityGroupRuleSet><item><securityGroupRuleId>sgr-1</securityGroupRuleId></item></securityGroupRuleSet></DescribeSecurityGroupRulesResponse>`,
		"DescribeNetworkInterfaces":  `<DescribeNetworkInterfacesResponse xmlns="` + ec2NS + `"><requestId>r</requestId><networkInterfaceSet><item><networkInterfaceId>eni-1</networkInterfaceId></item></networkInterfaceSet></DescribeNetworkInterfacesResponse>`,
		"DescribeInstances":          `<DescribeInstancesResponse xmlns="` + ec2NS + `"><requestId>r</requestId><reservationSet><item><instancesSet><item><instanceId>i-1</instanceId></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`,
		"DescribeVolumes":            `<DescribeVolumesResponse xmlns="` + ec2NS + `"><requestId>r</requestId><volumeSet><item><volumeId>vol-1</volumeId></item></volumeSet></DescribeVolumesResponse>`,
	}
}

// TestListEC2ReadsStubbedEndpoint proves the EC2 reader maps the in-tree
// read surface (VPCs through volumes) to records without a network: the
// stub speaks the Query protocol the SDK client already uses.
func TestListEC2ReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	responses := ec2Responses()
	server := httptest.NewServer(queryStub(t, responses, nil))
	defer server.Close()

	records, err := listEC2(context.Background(), stubConfig(server))
	if err != nil {
		t.Fatalf("listEC2 error = %v", err)
	}
	want := map[string]string{
		"vpc-1":    "main",
		"subnet-1": "subnet-1",
		"sg-1":     "web",
		"sgr-1":    "sgr-1",
		"eni-1":    "eni-1",
		"i-1":      "i-1",
		"vol-1":    "vol-1",
	}
	if len(records) != len(want) {
		t.Fatalf("len(records) = %d, want %d (%v)", len(records), len(want), records)
	}
	for _, record := range records {
		if want[record.ID] != record.Name {
			t.Errorf("record %q name = %q, want %q", record.ID, record.Name, want[record.ID])
		}
		if !strings.Contains(record.Detail, "region=us-east-1") {
			t.Errorf("record %q detail = %q, want region stamp", record.ID, record.Detail)
		}
	}
}

// TestListEC2FailsEachDeniedCall proves every EC2 paginator surfaces its
// call-site error: each action is denied in turn while the rest are served.
func TestListEC2FailsEachDeniedCall(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ action, wrap string }{
		{"DescribeVpcs", "ec2 describe VPCs"},
		{"DescribeSubnets", "ec2 describe subnets"},
		{"DescribeSecurityGroups", "ec2 describe security groups"},
		{"DescribeSecurityGroupRules", "ec2 describe security group rules"},
		{"DescribeNetworkInterfaces", "ec2 describe network interfaces"},
		{"DescribeInstances", "ec2 describe instances"},
		{"DescribeVolumes", "ec2 describe volumes"},
	} {
		cfg := stubServer(t, queryStub(t, ec2Responses(), map[string]bool{tc.action: true}))
		if _, err := listEC2(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.wrap) {
			t.Errorf("%s: error = %v, want %q", tc.action, err, tc.wrap)
		}
	}
}
