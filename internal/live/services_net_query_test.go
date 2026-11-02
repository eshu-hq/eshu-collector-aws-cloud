// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
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
		case "GetRolePolicy":
			serve(envelope("GetRolePolicy", `<RoleName>reader</RoleName><PolicyName>inline-reader</PolicyName><PolicyDocument>{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}</PolicyDocument>`))
		case "GetPolicy":
			serve(envelope("GetPolicy", `<Policy><PolicyName>ReadOnly</PolicyName><PolicyId>P1</PolicyId><Arn>arn:aws:iam::aws:policy/ReadOnlyAccess</Arn><Path>/</Path><DefaultVersionId>v1</DefaultVersionId><AttachmentCount>1</AttachmentCount></Policy>`))
		case "GetPolicyVersion":
			serve(envelope("GetPolicyVersion", `<PolicyVersion><Document>{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}}</Document><VersionId>v1</VersionId><IsDefaultVersion>true</IsDefaultVersion><CreateDate>2024-01-01T00:00:00Z</CreateDate></PolicyVersion>`))
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
		case "GetOpenIDConnectProvider":
			serve(envelope("GetOpenIDConnectProvider", `<Url>https://example.com</Url><ClientIDList><member>sts.amazonaws.com</member></ClientIDList><ThumbprintList><member>abc123</member></ThumbprintList>`))
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
	// Role and user rows keep dual emission (TypedOnly unset) until PR-D
	// deletes the transitional kinds; every row below carries its typed
	// home regardless.
	wantIAMHome := map[string]struct {
		kind      string
		typedOnly bool
	}{
		"reader":        {"aws_iam_role", false},
		"deployer":      {"aws_iam_user", false},
		"team-boundary": {"aws_iam_policy", true},
		"web":           {"aws_iam_instance_profile", true},
		"example.com":   {"aws_iam_oidc_provider", true},
	}
	for _, record := range records {
		home, ok := wantIAMHome[record.Name]
		if !ok {
			t.Errorf("unexpected IAM record %#v", record)
			continue
		}
		if record.Resource == nil || record.Resource.ResourceType != home.kind {
			t.Errorf("IAM record %q resource = %+v, want type %q", record.Name, record.Resource, home.kind)
		}
		if record.TypedOnly != home.typedOnly {
			t.Errorf("IAM record %q TypedOnly = %v, want %v", record.Name, record.TypedOnly, home.typedOnly)
		}
	}
	for _, record := range records {
		if record.Name != "reader" {
			continue
		}
		if len(record.IAMPermissionStatements) != 2 {
			t.Errorf("reader permission statements = %+v, want inline + managed", record.IAMPermissionStatements)
		}
	}
	for _, record := range records {
		if record.Resource == nil || record.Resource.ResourceID != "arn:aws:iam::123456789012:oidc-provider/example.com" {
			continue
		}
		if record.Resource.Attributes["issuer_url"] != "https://example.com" {
			t.Errorf("provider row lacks enriched issuer URL = %+v", record.Resource)
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
		case "GetTopicAttributes":
			serve(`<GetTopicAttributesResponse><GetTopicAttributesResult><Attributes><entry><key>DisplayName</key><value>orders</value></entry></Attributes></GetTopicAttributesResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetTopicAttributesResponse>`)
		case "ListSubscriptionsByTopic":
			serve(`<ListSubscriptionsByTopicResponse><ListSubscriptionsByTopicResult><Subscriptions><member><SubscriptionArn>arn:aws:sns:us-east-1:123456789012:orders:sub1</SubscriptionArn><Protocol>lambda</Protocol><Endpoint>arn:aws:lambda:us-east-1:123456789012:function:notify</Endpoint></member></Subscriptions></ListSubscriptionsByTopicResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></ListSubscriptionsByTopicResponse>`)
		default:
			t.Errorf("unexpected SNS action %q", r.Form.Get("Action"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	records, err := listSNS(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1 topic row carrying its subscription edges", len(records))
	}
	if records[0].Name != "orders" {
		t.Fatalf("sns topic name = %q, want display name", records[0].Name)
	}
	if records[0].Resource == nil || records[0].Resource.ResourceType != "aws_sns_topic" {
		t.Fatalf("sns topic resource = %+v, want typed home", records[0].Resource)
	}
	if !records[0].TypedOnly {
		t.Fatal("sns topic row must set TypedOnly")
	}
	if len(records[0].Relationships) != 1 || records[0].Relationships[0].RelationshipType != catalog.RelationshipSNSTopicDeliversToResource {
		t.Fatalf("sns subscription edges = %+v, want one delivers_to relationship", records[0].Relationships)
	}
}

func TestListSNSDeniedAttributesKeepsBareTopic(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		serve := func(body string) {
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write stub response: %v", err)
			}
		}
		switch r.Form.Get("Action") {
		case "ListTopics":
			serve(`<ListTopicsResponse><ListTopicsResult><Topics><member><TopicArn>arn:aws:sns:us-east-1:123456789012:orders</TopicArn></member></Topics></ListTopicsResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></ListTopicsResponse>`)
		case "GetTopicAttributes":
			w.WriteHeader(http.StatusForbidden)
			serve(`<ErrorResponse><Error><Type>Sender</Type><Code>AuthorizationError</Code><Message>denied</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
		case "ListSubscriptionsByTopic":
			serve(`<ListSubscriptionsByTopicResponse><ListSubscriptionsByTopicResult><Subscriptions></Subscriptions></ListSubscriptionsByTopicResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></ListSubscriptionsByTopicResponse>`)
		default:
			t.Errorf("unexpected SNS action %q", r.Form.Get("Action"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	records, err := listSNS(context.Background(), cfg)
	if err == nil {
		t.Fatal("denied attributes read must surface an optional denial, got nil error")
	}
	var denied *optionalReadDenied
	if !errors.As(err, &denied) {
		t.Fatalf("error type = %T, want *optionalReadDenied: %v", err, err)
	}
	if len(denied.denials) != 1 || denied.denials[0].operation != "GetTopicAttributes" {
		t.Fatalf("denials = %+v, want one GetTopicAttributes denial", denied.denials)
	}
	if len(records) != 1 {
		t.Fatalf("record count = %d, want the bare typed topic row", len(records))
	}
	if records[0].Resource == nil || records[0].Resource.ResourceType != "aws_sns_topic" {
		t.Fatalf("bare topic resource = %+v, want typed home", records[0].Resource)
	}
	if records[0].Name != "orders" {
		t.Fatalf("bare topic name = %q, want ARN fallback", records[0].Name)
	}
	if !records[0].TypedOnly {
		t.Fatal("bare topic row must set TypedOnly")
	}
}

func TestListSNSAttributesInternalErrorIsFatal(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		serve := func(body string) {
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write stub response: %v", err)
			}
		}
		switch r.Form.Get("Action") {
		case "ListTopics":
			serve(`<ListTopicsResponse><ListTopicsResult><Topics><member><TopicArn>arn:aws:sns:us-east-1:123456789012:orders</TopicArn></member></Topics></ListTopicsResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></ListTopicsResponse>`)
		case "GetTopicAttributes":
			w.WriteHeader(http.StatusInternalServerError)
			serve(`<ErrorResponse><Error><Type>Receiver</Type><Code>InternalError</Code><Message>boom</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
		default:
			t.Errorf("unexpected SNS action %q", r.Form.Get("Action"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	records, err := listSNS(context.Background(), cfg)
	if err == nil {
		t.Fatal("non-denial attributes failure must be fatal, got nil error")
	}
	var denied *optionalReadDenied
	if errors.As(err, &denied) {
		t.Fatalf("non-denial failure must not degrade to an optional denial: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("fatal attributes failure must keep no rows, got %d", len(records))
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
	if records[0].Resource == nil || records[0].Resource.ResourceType != "aws_sqs_queue" {
		t.Fatalf("sqs resource = %+v, want typed home", records[0].Resource)
	}
	if !records[0].TypedOnly {
		t.Fatal("sqs row must set TypedOnly")
	}
}
