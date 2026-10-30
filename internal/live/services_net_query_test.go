// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestListIAMListsRolesUsersPoliciesProfilesProviders(t *testing.T) {
	t.Parallel()

	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
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
		case "ListRoles":
			serve(envelope("ListRoles", `<Roles><member><RoleName>reader</RoleName><Arn>arn:aws:iam::123456789012:role/reader</Arn><Path>/</Path><RoleId>R1</RoleId><CreateDate>2024-01-01T00:00:00Z</CreateDate></member></Roles>`))
		case "GetRole":
			serve(envelope("GetRole", `<Role><RoleName>reader</RoleName><Arn>arn:aws:iam::123456789012:role/reader</Arn><Path>/</Path><RoleId>R1</RoleId><CreateDate>2024-01-01T00:00:00Z</CreateDate></Role>`))
		case "ListAttachedRolePolicies":
			serve(envelope("ListAttachedRolePolicies", `<AttachedPolicies><member><PolicyName>ReadOnly</PolicyName><PolicyArn>arn:aws:iam::aws:policy/ReadOnlyAccess</PolicyArn></member></AttachedPolicies>`))
		case "ListRolePolicies":
			serve(envelope("ListRolePolicies", `<PolicyNames><member>inline-reader</member></PolicyNames>`))
		case "ListUsers":
			serve(envelope("ListUsers", `<Users><member><UserName>deployer</UserName><Arn>arn:aws:iam::123456789012:user/deployer</Arn><Path>/</Path><UserId>U1</UserId><CreateDate>2024-01-01T00:00:00Z</CreateDate></member></Users>`))
		case "GetUser":
			serve(envelope("GetUser", `<User><UserName>deployer</UserName><Arn>arn:aws:iam::123456789012:user/deployer</Arn><Path>/</Path><UserId>U1</UserId><CreateDate>2024-01-01T00:00:00Z</CreateDate></User>`))
		case "ListAttachedUserPolicies":
			serve(envelope("ListAttachedUserPolicies", `<AttachedPolicies/>`))
		case "ListUserPolicies":
			serve(envelope("ListUserPolicies", `<PolicyNames/>`))
		case "ListPolicies":
			serve(envelope("ListPolicies", `<Policies><member><PolicyName>team-boundary</PolicyName><Arn>arn:aws:iam::123456789012:policy/team-boundary</Arn><Path>/</Path><PolicyId>P1</PolicyId></member></Policies>`))
		case "ListInstanceProfiles":
			serve(envelope("ListInstanceProfiles", `<InstanceProfiles><member><InstanceProfileName>web</InstanceProfileName><Arn>arn:aws:iam::123456789012:instance-profile/web</Arn><Path>/</Path><InstanceProfileId>F1</InstanceProfileId><CreateDate>2024-01-01T00:00:00Z</CreateDate></member></InstanceProfiles>`))
		case "ListOpenIDConnectProviders":
			serve(envelope("ListOpenIDConnectProviders", `<OpenIDConnectProviderList><member><Arn>arn:aws:iam::123456789012:oidc-provider/example.com</Arn></member></OpenIDConnectProviderList>`))
		default:
			t.Errorf("unexpected IAM action %q", r.Form.Get("Action"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	records, err := listIAM(context.Background(), cfg, identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 5 {
		t.Fatalf("record count = %d, want 5 (role, user, policy, profile, provider)", len(records))
	}
	names := map[string]bool{}
	for _, record := range records {
		names[record.Name] = true
	}
	for _, want := range []string{"reader", "deployer", "team-boundary", "web", "example.com"} {
		if !names[want] {
			t.Errorf("missing IAM record %q (got %v)", want, names)
		}
	}
}

func TestListSNSListsTopicsAndSubscriptions(t *testing.T) {
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
		switch r.Form.Get("Action") {
		case "ListTopics":
			serve(`<ListTopicsResponse><ListTopicsResult><Topics><member><TopicArn>arn:aws:sns:us-east-1:123456789012:orders</TopicArn></member></Topics></ListTopicsResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></ListTopicsResponse>`)
		case "ListSubscriptionsByTopic":
			serve(`<ListSubscriptionsByTopicResponse><ListSubscriptionsByTopicResult><Subscriptions><member><SubscriptionArn>arn:aws:sns:us-east-1:123456789012:orders:sub1</SubscriptionArn><Protocol>https</Protocol></member></Subscriptions></ListSubscriptionsByTopicResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></ListSubscriptionsByTopicResponse>`)
		default:
			t.Errorf("unexpected SNS action %q", r.Form.Get("Action"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	records, err := listSNS(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("record count = %d, want 2 (topic, subscription)", len(records))
	}
	if records[0].Name != "orders" || records[1].Name != "https" {
		t.Fatalf("sns records = %#v", records)
	}
}

func TestListSQSListsQueues(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.Header.Get("X-Amz-Target"), "ListQueues") {
			t.Errorf("unexpected SQS target %q", r.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		serveJSON(t, `{"QueueUrls": ["https://sqs.us-east-1.amazonaws.com/123456789012/orders"]}`)(w, r)
	}))

	records, err := listSQS(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1", len(records))
	}
	if records[0].Name != "orders" || !strings.Contains(records[0].ID, "sqs.us-east-1") {
		t.Fatalf("sqs record = %#v", records[0])
	}
}
