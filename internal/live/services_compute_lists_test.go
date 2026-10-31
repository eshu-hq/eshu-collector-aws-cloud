// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestListECRListsRepositoriesImagesAndPolicy(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch target := r.Header.Get("X-Amz-Target"); {
		case strings.HasSuffix(target, "DescribeRepositories"):
			serveJSON(t, `{"repositories": [{"repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/orders", "registryId": "123456789012", "repositoryName": "orders", "repositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/orders"}]}`)(w, r)
		case strings.HasSuffix(target, "ListTagsForResource"):
			serveJSON(t, `{"tags": [{"Key": "team", "Value": "checkout"}]}`)(w, r)
		case strings.HasSuffix(target, "DescribeImages"):
			serveJSON(t, `{"imageDetails": [{"registryId": "123456789012", "repositoryName": "orders", "imageDigest": "sha256:abc123", "imageTags": ["latest"]}]}`)(w, r)
		case strings.HasSuffix(target, "GetLifecyclePolicy"):
			serveJSON(t, `{"registryId": "123456789012", "repositoryName": "orders", "lifecyclePolicyText": "{\"rules\":[]}"}`)(w, r)
		default:
			t.Errorf("unexpected ECR target %q", target)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	records, err := listECR(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, record := range records {
		if record.Resource == nil {
			continue
		}
		kinds[record.Resource.ResourceType] = true
	}
	for _, want := range []string{"aws_ecr_repository", "aws_ecr_lifecycle_policy"} {
		if !kinds[want] {
			t.Errorf("missing ECR resource %q (got %v, %d records)", want, kinds, len(records))
		}
	}
	if len(records) < 3 {
		t.Errorf("record count = %d, want at least 3 (repository, image, policy)", len(records))
	}
}

func TestListELBV2ListsBalancersListenersRulesTargetGroups(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		serve := func(body string) {
			w.Header().Set("Content-Type", "text/xml")
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write stub response: %v", err)
			}
		}
		envelope := func(action, result string) string {
			return `<` + action + `Response><` + action + `Result>` + result + `</` + action + `Result><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></` + action + `Response>`
		}
		switch r.Form.Get("Action") {
		case "DescribeLoadBalancers":
			serve(envelope("DescribeLoadBalancers", `<LoadBalancers><member><LoadBalancerArn>arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/orders/abc</LoadBalancerArn><LoadBalancerName>orders</LoadBalancerName><Type>application</Type></member></LoadBalancers>`))
		case "DescribeListeners":
			serve(envelope("DescribeListeners", `<Listeners><member><ListenerArn>arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/orders/abc/def</ListenerArn><Port>443</Port><Protocol>HTTPS</Protocol></member></Listeners>`))
		case "DescribeRules":
			serve(envelope("DescribeRules", `<Rules><member><RuleArn>arn:aws:elasticloadbalancing:us-east-1:123456789012:listener-rule/app/orders/abc/def/ghi</RuleArn><Priority>1</Priority></member></Rules>`))
		case "DescribeTargetGroups":
			serve(envelope("DescribeTargetGroups", `<TargetGroups><member><TargetGroupArn>arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/orders-tg/jkl</TargetGroupArn><TargetGroupName>orders-tg</TargetGroupName></member></TargetGroups>`))
		default:
			t.Errorf("unexpected ELBv2 action %q", r.Form.Get("Action"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	records, err := listELBV2(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 {
		t.Fatalf("record count = %d, want 4 (balancer, listener, rule, target group)", len(records))
	}
	want := map[string]string{
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/orders/abc":          "orders",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/orders/abc/def":          "def",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:listener-rule/app/orders/abc/def/ghi": "ghi",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/orders-tg/jkl":            "orders-tg",
	}
	for _, record := range records {
		name, ok := want[record.ID]
		if !ok {
			t.Errorf("unexpected ELBv2 record %#v", record)
			continue
		}
		if record.Name != name {
			t.Errorf("ELBv2 record %q name = %q, want %q", record.ID, record.Name, name)
		}
		delete(want, record.ID)
	}
	for id := range want {
		t.Errorf("missing ELBv2 record %q", id)
	}
}
