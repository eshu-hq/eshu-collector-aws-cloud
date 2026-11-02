// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// TestIAMManagedPolicyFanoutBoundedAt25 pins the per-principal document cap:
// 30 attachments must cost at most 25 GetPolicy reads. The five skipped
// attachments are reported through the truncation warning, not silence.
func TestIAMManagedPolicyFanoutBoundedAt25(t *testing.T) {
	t.Parallel()

	api := iamPermissionRoleFixture()
	api.attached = nil
	for i := 0; i < 30; i++ {
		arn := iamPermissionManagedARN + "-extra"
		api.attached = append(api.attached, arn)
	}
	api.managed[iamPermissionManagedARN+"-extra"] = iamPermissionManagedDocument
	api.inline = nil
	api.inlineBy = map[string]string{}
	rows, err := listIAMRoleRecords(context.Background(), api, "us-east-1",
		VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	denied, ok := err.(*optionalReadDenied)
	if !ok {
		t.Fatalf("fanout err = %v, want the truncation denial carrier", err)
	}
	found := false
	for _, entry := range denied.denials {
		if entry.effect == "permission-statements-truncated" {
			found = true
		}
	}
	if !found {
		t.Fatalf("denials = %+v, want the truncation entry", denied.denials)
	}
	if api.getCalls != 25 {
		t.Fatalf("GetPolicy calls = %d, want bounded 25", api.getCalls)
	}
	if len(rows) != 1 || len(rows[0].IAMPermissionStatements) != 25 {
		t.Fatalf("statements = %+v, want 25 bounded", rows[0].IAMPermissionStatements)
	}
}

// TestIAMPolicyDocumentDenialWarnsWithoutSilence pins the degradation
// contract: a denied document keeps the surviving statements and records one
// warning, so the principal never reads back as silently empty.
func TestIAMPolicyDocumentDenialWarnsWithoutSilence(t *testing.T) {
	t.Parallel()

	api := iamPermissionRoleFixture()
	api.denyGet = map[string]bool{"inline-read": true}
	rows, err := listIAMRoleRecords(context.Background(), api, "us-east-1",
		VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	denied, ok := err.(*optionalReadDenied)
	if !ok || len(denied.denials) != 1 {
		t.Fatalf("denial = %+v err=%v, want one optional denial", denied, err)
	}
	entry := denied.denials[0]
	if entry.operation != "GetRolePolicy" || entry.resource != "role:demo" || entry.effect == "" {
		t.Fatalf("denial entry = %+v, want operation/resource/effect", entry)
	}
	if len(rows) != 1 || len(rows[0].IAMPermissionStatements) != 1 {
		t.Fatalf("surviving rows = %+v, want managed statement kept", rows)
	}
	if rows[0].IAMPermissionStatements[0].PolicySource != "attached_managed" {
		t.Fatalf("survivor = %+v, want managed statement", rows[0].IAMPermissionStatements[0])
	}
}

// TestIAMManagedPolicyTruncationWarnsWithoutSilence pins the cap
// contract: attachments past the per-principal document cap keep their
// surviving statements and record one truncation warning, so "25 of 30"
// never reads back as a complete "all".
func TestIAMManagedPolicyTruncationWarnsWithoutSilence(t *testing.T) {
	t.Parallel()

	api := iamPermissionRoleFixture()
	api.attached = nil
	for i := 0; i < 30; i++ {
		arn := iamPermissionManagedARN + "-extra"
		api.attached = append(api.attached, arn)
	}
	api.managed[iamPermissionManagedARN+"-extra"] = iamPermissionManagedDocument
	api.inline = nil
	api.inlineBy = map[string]string{}
	rows, err := listIAMRoleRecords(context.Background(), api, "us-east-1",
		VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	denied, ok := err.(*optionalReadDenied)
	if !ok {
		t.Fatalf("truncation err = %v, want one optional denial", err)
	}
	found := false
	for _, entry := range denied.denials {
		if entry.effect != "permission-statements-truncated" {
			continue
		}
		found = true
		if entry.resource != "role:demo" {
			t.Fatalf("truncation resource = %q, want role:demo", entry.resource)
		}
		if entry.attributes["attached"] != 30 || entry.attributes["read"] != 25 {
			t.Fatalf("truncation attributes = %v, want attached=30 read=25", entry.attributes)
		}
		if want := "managed policy reads capped for role:demo: 25 of 30 attached policies read; remaining statements unavailable"; entry.message != want {
			t.Fatalf("truncation message = %q, want %q", entry.message, want)
		}
	}
	if !found {
		t.Fatalf("denials = %+v, want one permission-statements-truncated entry", denied.denials)
	}
	if len(rows) != 1 || len(rows[0].IAMPermissionStatements) != 25 {
		t.Fatalf("surviving statements = %+v, want 25 kept", rows[0].IAMPermissionStatements)
	}
}

// TestIAMManagedPolicyWithoutDefaultVersionWarns pins the unreadable
// policy contract: a managed policy with no default version cannot yield
// statements, so it records one warning instead of vanishing silently.
func TestIAMManagedPolicyWithoutDefaultVersionWarns(t *testing.T) {
	t.Parallel()

	api := iamPermissionRoleFixture()
	api.inline = nil
	api.inlineBy = map[string]string{}
	api.noDefaultVersion = map[string]bool{iamPermissionManagedARN: true}
	rows, err := listIAMRoleRecords(context.Background(), api, "us-east-1",
		VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	denied, ok := err.(*optionalReadDenied)
	if !ok {
		t.Fatalf("missing-version err = %v, want one optional denial", err)
	}
	found := false
	for _, entry := range denied.denials {
		if entry.effect == "permission-statements-unavailable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("denials = %+v, want one permission-statements-unavailable entry", denied.denials)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want the surviving row kept", len(rows))
	}
}

// TestIAMUserPolicyDenialWarnsWithoutSilence mirrors the role denial
// contract on the user path: a denied inline read keeps the surviving
// statements and records one warning.
func TestIAMUserPolicyDenialWarnsWithoutSilence(t *testing.T) {
	t.Parallel()

	arn := "arn:aws:iam::123456789012:user/deploy"
	api := &fakeIAMPermissionUserAPI{
		user:    iamtypes.User{Arn: aws.String(arn), UserName: aws.String("deploy"), Path: aws.String("/")},
		inline:  []string{"inline-deploy"},
		byName:  map[string]string{"inline-deploy": iamPermissionInlineDocument},
		byARN:   map[string]string{iamPermissionManagedARN: iamPermissionManagedDocument},
		denyGet: map[string]bool{"inline-deploy": true},
	}
	rows, err := listIAMUserRecords(context.Background(), api, "us-east-1",
		VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	denied, ok := err.(*optionalReadDenied)
	if !ok || len(denied.denials) != 1 {
		t.Fatalf("denial = %+v err=%v, want one optional denial", denied, err)
	}
	if entry := denied.denials[0]; entry.operation != "GetUserPolicy" || entry.resource != "user:deploy" {
		t.Fatalf("denial entry = %+v, want GetUserPolicy on user:deploy", entry)
	}
	if len(rows) != 1 || len(rows[0].IAMPermissionStatements) == 0 {
		t.Fatalf("surviving rows = %+v, want managed statements kept", rows)
	}
}
