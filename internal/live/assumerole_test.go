// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const stubAssumeRoleResponse = `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">` +
	`<AssumeRoleResult><AssumedRoleUser><Arn>arn:aws:sts::111122223333:assumed-role/r/s</Arn>` +
	`<AssumedRoleId>AROA:session</AssumedRoleId></AssumedRoleUser><Credentials>` +
	`<AccessKeyId>ASSUMEDKEY</AccessKeyId><SecretAccessKey>assumedsecret</SecretAccessKey>` +
	`<SessionToken>assumedtoken</SessionToken>` +
	`<Expiration>2030-01-01T00:00:00Z</Expiration></Credentials>` +
	`<PackedPolicySize>0</PackedPolicySize></AssumeRoleResult>` +
	`<ResponseMetadata><RequestId>stub</RequestId></ResponseMetadata></AssumeRoleResponse>`

// stubSTSClient points a real STS client at a stub HTTP endpoint so the
// assume exchange is asserted end to end: the request the production code
// sends, not a fake of it.
func stubSTSClient(t *testing.T, handler http.HandlerFunc) newSTSClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return func(cfg aws.Config) *sts.Client {
		cfg.BaseEndpoint = aws.String(server.URL)
		return sts.NewFromConfig(cfg)
	}
}

func stubBaseConfig() aws.Config {
	return aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKID", "SECRET", "TOKEN"),
	}
}

// TestAssumeScopeRoleSendsExternalID proves the production exchange carries
// the scope role ARN, external ID, and session name to STS, and the returned
// config issues the assumed credentials.
func TestAssumeScopeRoleSendsExternalID(t *testing.T) {
	t.Parallel()

	const role = "arn:aws:iam::111122223333:role/irsa-eshu-aws-collector-cross-account-role"
	var gotAction, gotRole, gotExternal, gotSession string
	newClient := stubSTSClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading stub request: %v", err)
		}
		query, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("parsing stub request: %v", err)
		}
		gotAction, gotRole, gotExternal, gotSession = query.Get("Action"), query.Get("RoleArn"),
			query.Get("ExternalId"), query.Get("RoleSessionName")
		w.Header().Set("Content-Type", "text/xml")
		if _, err := io.WriteString(w, stubAssumeRoleResponse); err != nil {
			t.Errorf("writing stub response: %v", err)
		}
	})
	assumed, err := assumeWithClient(context.Background(), stubBaseConfig(), role, "eshu-ops-qa-collector", newClient)
	if err != nil {
		t.Fatalf("assumeWithClient error = %v", err)
	}
	if gotAction != "AssumeRole" || gotRole != role ||
		gotExternal != "eshu-ops-qa-collector" || gotSession != scopeSessionName {
		t.Fatalf("STS request = %q %q %q %q, want AssumeRole with scope role, external ID, session name",
			gotAction, gotRole, gotExternal, gotSession)
	}
	creds, err := assumed.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("Retrieve error = %v", err)
	}
	if creds.AccessKeyID != "ASSUMEDKEY" {
		t.Fatalf("AccessKeyID = %q, want the stubbed assumed key", creds.AccessKeyID)
	}
}

// TestAssumeScopeRoleWrapperUsesStubEndpoint proves the production entry
// point — not just the injectable helper — carries the scope role ARN,
// external ID, and session name to STS and returns usable credentials.
func TestAssumeScopeRoleWrapperUsesStubEndpoint(t *testing.T) {
	t.Parallel()

	const role = "arn:aws:iam::111122223333:role/irsa-eshu-aws-collector-cross-account-role"
	var gotRole, gotExternal, gotSession string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading stub request: %v", err)
			return
		}
		query, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("parsing stub request: %v", err)
			return
		}
		gotRole, gotExternal, gotSession = query.Get("RoleArn"), query.Get("ExternalId"), query.Get("RoleSessionName")
		w.Header().Set("Content-Type", "text/xml")
		if _, err := io.WriteString(w, stubAssumeRoleResponse); err != nil {
			t.Errorf("writing stub response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	base := stubBaseConfig()
	base.BaseEndpoint = aws.String(server.URL)
	assumed, err := AssumeScopeRole(context.Background(), base, role, "eshu-ops-qa-collector")
	if err != nil {
		t.Fatalf("AssumeScopeRole error = %v", err)
	}
	if gotRole != role || gotExternal != "eshu-ops-qa-collector" || gotSession != scopeSessionName {
		t.Fatalf("STS request = %q %q %q, want scope role, external ID, session name",
			gotRole, gotExternal, gotSession)
	}
	creds, err := assumed.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("Retrieve error = %v", err)
	}
	if creds.AccessKeyID != "ASSUMEDKEY" {
		t.Fatalf("AccessKeyID = %q, want the stubbed assumed key", creds.AccessKeyID)
	}
}

// TestAssumeScopeRoleFailsFast proves an STS denial fails the exchange here
// with the role named, instead of surfacing later as generic verification
// noise.
func TestAssumeScopeRoleFailsFast(t *testing.T) {
	t.Parallel()

	newClient := stubSTSClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusForbidden)
		if _, err := io.WriteString(w, `<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`); err != nil {
			t.Errorf("writing stub error: %v", err)
		}
	})
	const role = "arn:aws:iam::111122223333:role/denied"
	_, err := assumeWithClient(context.Background(), stubBaseConfig(), role, "eshu-ops-qa-collector", newClient)
	if err == nil || !strings.Contains(err.Error(), role) {
		t.Fatalf("assumeWithClient error = %v, want the denial naming %s", err, role)
	}
}
