// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package cognito

import (
	"reflect"
	"testing"

	awscloud "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

func testBoundary() awscloud.Boundary {
	return awscloud.Boundary{
		AccountID:    "123456789012",
		Region:       "us-east-1",
		ServiceKind:  catalog.ServiceCognito,
		ScopeID:      "scope-1",
		GenerationID: "gen-1",
	}
}

// TestPortParity_UserPoolClientUsesPool freezes the client-to-pool edge,
// including the pool-ID fallback when the pool ARN is absent.
func TestPortParity_UserPoolClientUsesPool(t *testing.T) {
	t.Parallel()
	client := UserPoolClient{ID: "abc123", UserPoolID: "us-east-1_aaaaaa"}
	poolARN := "arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_aaaaaa"
	got := userPoolClientRelationship(testBoundary(), client, poolARN)
	want := &awscloud.RelationshipObservation{
		Boundary:         testBoundary(),
		RelationshipType: catalog.RelationshipCognitoUserPoolClientUsesUserPool,
		SourceResourceID: "abc123",
		TargetResourceID: poolARN,
		TargetARN:        poolARN,
		TargetType:       catalog.ResourceTypeCognitoUserPool,
		SourceRecordID:   "abc123#user-pool#us-east-1_aaaaaa",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("userPoolClientRelationship() = %#v, want %#v", got, want)
	}
	fallback := userPoolClientRelationship(testBoundary(), client, "  ")
	if fallback == nil || fallback.TargetResourceID != "us-east-1_aaaaaa" || fallback.TargetARN != "" {
		t.Fatalf("pool-ARN fallback = %#v, want pool-ID target with empty ARN", fallback)
	}
	if got := userPoolClientRelationship(testBoundary(), UserPoolClient{}, poolARN); got != nil {
		t.Fatalf("empty client = %#v, want nil", got)
	}
}

// TestPortParity_UserPoolLambdaTriggers freezes per-slot trigger edges and
// the blank-ARN skip.
func TestPortParity_UserPoolLambdaTriggers(t *testing.T) {
	t.Parallel()
	pool := UserPool{
		ID:  "us-east-1_aaaaaa",
		ARN: "arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_aaaaaa",
		LambdaTriggers: []LambdaTrigger{
			{Trigger: "PreSignUp", ARN: "arn:aws:lambda:us-east-1:123456789012:function:pre"},
			{Trigger: "PostConfirmation", ARN: "  "},
		},
	}
	got := userPoolLambdaTriggerRelationships(testBoundary(), pool)
	if len(got) != 1 {
		t.Fatalf("trigger edges = %#v, want exactly 1 (blank ARN skipped)", got)
	}
	edge := got[0]
	if edge.TargetType != catalog.ResourceTypeLambdaFunction {
		t.Fatalf("trigger target type = %q", edge.TargetType)
	}
	if edge.SourceRecordID != pool.ARN+"#lambda-trigger#PreSignUp#arn:aws:lambda:us-east-1:123456789012:function:pre" {
		t.Fatalf("trigger record id = %q", edge.SourceRecordID)
	}
	if attrs := edge.Attributes; attrs["trigger"] != "PreSignUp" {
		t.Fatalf("trigger attributes = %#v", attrs)
	}
}

// TestPortParity_IdentityPoolProviders freezes the provider-name to pool-ID
// reduction (the dangling-edge guard) and the stable SAML-before-OIDC order.
func TestPortParity_IdentityPoolProviders(t *testing.T) {
	t.Parallel()
	pool := IdentityPool{
		ID:  "us-east-1:bbbbbb",
		ARN: "arn:aws:cognito-identity:us-east-1:123456789012:identitypool/us-east-1:bbbbbb",
		UserPoolProviders: []IdentityPoolUserPoolProvider{{
			ProviderName: "cognito-idp.us-east-1.amazonaws.com/us-east-1_aaaaaa",
			ClientID:     "abc123",
		}},
		SAMLProviderARNs:          []string{"arn:aws:iam::123456789012:saml-provider/okta", " "},
		OpenIDConnectProviderARNs: []string{"arn:aws:iam::123456789012:oidc-provider/auth.example.com"},
	}
	got := identityPoolRelationships(testBoundary(), pool)
	if len(got) != 3 {
		t.Fatalf("identity pool edges = %#v, want 3", got)
	}
	userEdge := got[0]
	if userEdge.TargetResourceID != "us-east-1_aaaaaa" {
		t.Fatalf("provider target = %q, want the bare pool ID (not the compound provider name)", userEdge.TargetResourceID)
	}
	if userEdge.Attributes["user_pool_id"] != "us-east-1_aaaaaa" {
		t.Fatalf("provider attributes = %#v", userEdge.Attributes)
	}
	if got[1].TargetResourceID != "arn:aws:iam::123456789012:saml-provider/okta" {
		t.Fatalf("SAML edge = %#v, want SAML before OIDC", got[1])
	}
	if got[2].TargetType != identityProviderTargetType {
		t.Fatalf("OIDC edge target type = %q, want %q", got[2].TargetType, identityProviderTargetType)
	}
}

// TestPortParity_UserPoolIDFromProviderName freezes the final-segment
// extraction and the unchanged-fallback for unexpected shapes.
func TestPortParity_UserPoolIDFromProviderName(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"cognito-idp.us-east-1.amazonaws.com/us-east-1_aaaaaa", "us-east-1_aaaaaa"},
		{"  cognito-idp.us-east-1.amazonaws.com/us-east-1_aaaaaa  ", "us-east-1_aaaaaa"},
		{"bare-pool-id", "bare-pool-id"},
		{"trailing-slash/", "trailing-slash/"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := userPoolIDFromProviderName(tc.in); got != tc.want {
			t.Errorf("userPoolIDFromProviderName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestPortParity_ExternalProviderARNs freezes the stable SAML-then-OIDC
// order and blank skipping.
func TestPortParity_ExternalProviderARNs(t *testing.T) {
	t.Parallel()
	pool := IdentityPool{
		SAMLProviderARNs:          []string{"", "arn:saml"},
		OpenIDConnectProviderARNs: []string{"arn:oidc"},
	}
	want := []string{"arn:saml", "arn:oidc"}
	if got := externalProviderARNs(pool); !reflect.DeepEqual(got, want) {
		t.Fatalf("externalProviderARNs() = %#v, want %#v", got, want)
	}
	if got := externalProviderARNs(IdentityPool{}); got != nil {
		t.Fatalf("externalProviderARNs(empty) = %#v, want nil", got)
	}
}
