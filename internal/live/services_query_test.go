// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"strings"
	"testing"
)

// queryEnvelope wraps a Query-protocol result body in its response envelope.
func queryEnvelope(action, xmlns, result string) string {
	return `<` + action + `Response xmlns="` + xmlns + `"><` + action + `Result>` +
		result + `</` + action + `Result><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></` + action + `Response>`
}

func rdsResponses() map[string]string {
	xmlns := "http://rds.amazonaws.com/doc/2014-10-31/"
	return map[string]string{
		"DescribeDBInstances": queryEnvelope("DescribeDBInstances", xmlns,
			`<DBInstances><DBInstance><DBInstanceIdentifier>db-1</DBInstanceIdentifier><DBInstanceArn>arn:aws:rds:us-east-1:1:db:db-1</DBInstanceArn></DBInstance></DBInstances>`),
		"DescribeDBClusters": queryEnvelope("DescribeDBClusters", xmlns,
			`<DBClusters><DBCluster><DBClusterIdentifier>c-1</DBClusterIdentifier><DBClusterArn>arn:aws:rds:us-east-1:1:cluster:c-1</DBClusterArn></DBCluster></DBClusters>`),
		"DescribeDBSubnetGroups": queryEnvelope("DescribeDBSubnetGroups", xmlns,
			`<DBSubnetGroups><DBSubnetGroup><DBSubnetGroupName>g-1</DBSubnetGroupName><DBSubnetGroupArn>arn:aws:rds:us-east-1:1:subgrp:g-1</DBSubnetGroupArn></DBSubnetGroup></DBSubnetGroups>`),
	}
}

func TestListRDSReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	cfg := stubServer(t, queryStub(t, rdsResponses(), nil))

	records, err := listRDS(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listRDS error = %v", err)
	}
	want := map[string]string{
		"arn:aws:rds:us-east-1:1:db:db-1":     "db-1",
		"arn:aws:rds:us-east-1:1:cluster:c-1": "c-1",
		"arn:aws:rds:us-east-1:1:subgrp:g-1":  "g-1",
	}
	if len(records) != len(want) {
		t.Fatalf("len(records) = %d, want %d (%v)", len(records), len(want), records)
	}
	for _, record := range records {
		if want[record.ID] != record.Name {
			t.Errorf("record %q name = %q, want %q", record.ID, record.Name, want[record.ID])
		}
	}

	for _, tc := range []struct{ action, wrap string }{
		{"DescribeDBInstances", "rds describe DB instances"},
		{"DescribeDBClusters", "rds describe DB clusters"},
		{"DescribeDBSubnetGroups", "rds describe DB subnet groups"},
	} {
		cfg := stubServer(t, queryStub(t, rdsResponses(), map[string]bool{tc.action: true}))
		if _, err := listRDS(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.wrap) {
			t.Errorf("%s: error = %v, want %q", tc.action, err, tc.wrap)
		}
	}
}

func elbv2Responses() map[string]string {
	xmlns := "https://elasticloadbalancing.amazonaws.com/doc/2015-12-01/"
	return map[string]string{
		"DescribeLoadBalancers": queryEnvelope("DescribeLoadBalancers", xmlns,
			`<LoadBalancers><member><LoadBalancerArn>arn:lb</LoadBalancerArn><LoadBalancerName>lb-1</LoadBalancerName></member></LoadBalancers>`),
		"DescribeListeners": queryEnvelope("DescribeListeners", xmlns,
			`<Listeners><member><ListenerArn>arn:lb/listener/l1</ListenerArn></member></Listeners>`),
		"DescribeRules": queryEnvelope("DescribeRules", xmlns,
			`<Rules><member><RuleArn>arn:lb/listener/l1/rule/r1</RuleArn></member></Rules>`),
		"DescribeTargetGroups": queryEnvelope("DescribeTargetGroups", xmlns,
			`<TargetGroups><member><TargetGroupArn>arn:tg</TargetGroupArn><TargetGroupName>tg-1</TargetGroupName></member></TargetGroups>`),
	}
}

func TestListELBV2ReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	cfg := stubServer(t, queryStub(t, elbv2Responses(), nil))

	records, err := listELBV2(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listELBV2 error = %v", err)
	}
	want := map[string]string{
		"arn:lb":                     "lb-1",
		"arn:lb/listener/l1":         "l1",
		"arn:lb/listener/l1/rule/r1": "r1",
		"arn:tg":                     "tg-1",
	}
	if len(records) != len(want) {
		t.Fatalf("len(records) = %d, want %d (%v)", len(records), len(want), records)
	}
	for _, record := range records {
		if want[record.ID] != record.Name {
			t.Errorf("record %q name = %q, want %q", record.ID, record.Name, want[record.ID])
		}
	}

	for _, tc := range []struct{ action, wrap string }{
		{"DescribeLoadBalancers", "elbv2 describe load balancers"},
		{"DescribeListeners", "elbv2 describe listeners"},
		{"DescribeRules", "elbv2 describe rules"},
		{"DescribeTargetGroups", "elbv2 describe target groups"},
	} {
		cfg := stubServer(t, queryStub(t, elbv2Responses(), map[string]bool{tc.action: true}))
		if _, err := listELBV2(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.wrap) {
			t.Errorf("%s: error = %v, want %q", tc.action, err, tc.wrap)
		}
	}
}

func iamResponses() map[string]string {
	xmlns := "https://iam.amazonaws.com/doc/2010-05-08/"
	return map[string]string{
		"ListRoles": queryEnvelope("ListRoles", xmlns,
			`<Roles><member><RoleName>role-1</RoleName><Arn>arn:aws:iam::1:role/role-1</Arn></member></Roles>`),
		"ListUsers": queryEnvelope("ListUsers", xmlns,
			`<Users><member><UserName>user-1</UserName><Arn>arn:aws:iam::1:user/user-1</Arn></member></Users>`),
		"ListPolicies": queryEnvelope("ListPolicies", xmlns,
			`<Policies><member><PolicyName>p-1</PolicyName><Arn>arn:aws:iam::1:policy/p-1</Arn></member></Policies>`),
		"ListInstanceProfiles": queryEnvelope("ListInstanceProfiles", xmlns,
			`<InstanceProfiles><member><InstanceProfileName>ip-1</InstanceProfileName><Arn>arn:aws:iam::1:instance-profile/ip-1</Arn></member></InstanceProfiles>`),
		"ListOpenIDConnectProviders": queryEnvelope("ListOpenIDConnectProviders", xmlns,
			`<OpenIDConnectProviderList><member><Arn>arn:aws:iam::1:oidc-provider/id.example.com</Arn></member></OpenIDConnectProviderList>`),
	}
}

func TestListIAMReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	cfg := stubServer(t, queryStub(t, iamResponses(), nil))

	records, err := listIAM(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listIAM error = %v", err)
	}
	want := map[string]string{
		"arn:aws:iam::1:role/role-1":                  "role-1",
		"arn:aws:iam::1:user/user-1":                  "user-1",
		"arn:aws:iam::1:policy/p-1":                   "p-1",
		"arn:aws:iam::1:instance-profile/ip-1":        "ip-1",
		"arn:aws:iam::1:oidc-provider/id.example.com": "id.example.com",
	}
	if len(records) != len(want) {
		t.Fatalf("len(records) = %d, want %d (%v)", len(records), len(want), records)
	}
	for _, record := range records {
		if want[record.ID] != record.Name {
			t.Errorf("record %q name = %q, want %q", record.ID, record.Name, want[record.ID])
		}
	}

	for _, tc := range []struct{ action, wrap string }{
		{"ListRoles", "iam list roles"},
		{"ListUsers", "iam list users"},
		{"ListPolicies", "iam list policies"},
		{"ListInstanceProfiles", "iam list instance profiles"},
		{"ListOpenIDConnectProviders", "iam list OIDC providers"},
	} {
		cfg := stubServer(t, queryStub(t, iamResponses(), map[string]bool{tc.action: true}))
		if _, err := listIAM(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.wrap) {
			t.Errorf("%s: error = %v, want %q", tc.action, err, tc.wrap)
		}
	}
}

func snsResponses() map[string]string {
	xmlns := "http://sns.amazonaws.com/doc/2010-03-31/"
	return map[string]string{
		"ListTopics": queryEnvelope("ListTopics", xmlns,
			`<Topics><member><TopicArn>arn:aws:sns:us-east-1:1:topic-1</TopicArn></member></Topics>`),
		"ListSubscriptionsByTopic": queryEnvelope("ListSubscriptionsByTopic", xmlns,
			`<Subscriptions><member><SubscriptionArn>arn:aws:sns:us-east-1:1:sub-1</SubscriptionArn><Protocol>email</Protocol></member></Subscriptions>`),
	}
}

func TestListSNSReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	cfg := stubServer(t, queryStub(t, snsResponses(), nil))

	records, err := listSNS(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listSNS error = %v", err)
	}
	want := map[string]string{
		"arn:aws:sns:us-east-1:1:topic-1": "topic-1",
		"arn:aws:sns:us-east-1:1:sub-1":   "email",
	}
	if len(records) != len(want) {
		t.Fatalf("len(records) = %d, want %d (%v)", len(records), len(want), records)
	}
	for _, record := range records {
		if want[record.ID] != record.Name {
			t.Errorf("record %q name = %q, want %q", record.ID, record.Name, want[record.ID])
		}
	}

	for _, tc := range []struct{ action, wrap string }{
		{"ListTopics", "sns list topics"},
		{"ListSubscriptionsByTopic", "sns list subscriptions"},
	} {
		cfg := stubServer(t, queryStub(t, snsResponses(), map[string]bool{tc.action: true}))
		if _, err := listSNS(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.wrap) {
			t.Errorf("%s: error = %v, want %q", tc.action, err, tc.wrap)
		}
	}
}
