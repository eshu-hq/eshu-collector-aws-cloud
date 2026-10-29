// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestEC2RuleDenialKeepsCoreResourcesAndLaterReads(t *testing.T) {
	for _, code := range []string{"UnauthorizedOperation", "Throttling"} {
		t.Run(code, func(t *testing.T) {
			calls := map[string]int{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				serve := func(body string) {
					if _, err := w.Write([]byte(body)); err != nil {
						t.Errorf("write fixture response: %v", err)
					}
				}
				if err := r.ParseForm(); err != nil {
					t.Error(err)
					return
				}
				action := r.Form.Get("Action")
				calls[action]++
				w.Header().Set("Content-Type", "text/xml")
				if action == "DescribeSecurityGroupRules" {
					w.WriteHeader(http.StatusForbidden)
					serve(fmt.Sprintf(`<Response><Errors><Error><Code>%s</Code><Message>denied</Message></Error></Errors><RequestID>x</RequestID></Response>`, code))
					return
				}
				if action == "DescribeVpcs" {
					serve(`<DescribeVpcsResponse><requestId>x</requestId><vpcSet><item><vpcId>vpc-123</vpcId></item></vpcSet></DescribeVpcsResponse>`)
					return
				}
				if action == "DescribeInstances" {
					serve(`<DescribeInstancesResponse><requestId>x</requestId><reservationSet><item><reservationId>r-123</reservationId><instancesSet><item><instanceId>i-123</instanceId></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`)
					return
				}
				serve(fmt.Sprintf(`<%sResponse><requestId>x</requestId></%sResponse>`, action, action))
			}))
			defer server.Close()
			cfg := aws.Config{
				Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(),
				Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
					return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
				}),
			}
			records, err := listEC2(context.Background(), cfg, VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
			if code == "Throttling" {
				if err == nil || len(records) != 0 || calls["DescribeInstances"] != 0 {
					t.Fatalf("required failure records=%d err=%v calls=%v", len(records), err, calls)
				}
				return
			}
			if _, ok := err.(*optionalReadDenied); !ok {
				t.Fatalf("denial class = %T: %v", err, err)
			}
			if calls["DescribeInstances"] != 1 || calls["DescribeVolumes"] != 1 {
				t.Fatalf("later EC2 reads skipped: %v", calls)
			}
			var vpc, instance bool
			for _, row := range records {
				if row.Resource == nil {
					continue
				}
				switch row.Resource.ResourceID {
				case "vpc-123":
					vpc = true
				case "i-123":
					instance = true
				}
			}
			if !vpc || !instance {
				t.Fatalf("core records lost: vpc=%t instance=%t records=%d", vpc, instance, len(records))
			}
		})
	}
}
