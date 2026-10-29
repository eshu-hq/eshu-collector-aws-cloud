// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type fakeIAMUserAPI struct{ user iamtypes.User }

func (f fakeIAMUserAPI) ListUsers(context.Context, *awsiam.ListUsersInput, ...func(*awsiam.Options)) (*awsiam.ListUsersOutput, error) {
	return &awsiam.ListUsersOutput{Users: []iamtypes.User{f.user}}, nil
}
func (f fakeIAMUserAPI) GetUser(context.Context, *awsiam.GetUserInput, ...func(*awsiam.Options)) (*awsiam.GetUserOutput, error) {
	return &awsiam.GetUserOutput{User: &f.user}, nil
}
func (f fakeIAMUserAPI) ListAttachedUserPolicies(context.Context, *awsiam.ListAttachedUserPoliciesInput, ...func(*awsiam.Options)) (*awsiam.ListAttachedUserPoliciesOutput, error) {
	return &awsiam.ListAttachedUserPoliciesOutput{}, nil
}
func (f fakeIAMUserAPI) ListUserPolicies(context.Context, *awsiam.ListUserPoliciesInput, ...func(*awsiam.Options)) (*awsiam.ListUserPoliciesOutput, error) {
	return &awsiam.ListUserPoliciesOutput{}, nil
}

func TestIAMUserResourceGlobalAndNilPolicies(t *testing.T) {
	arn := "arn:aws:iam::123456789012:user/team/demo"
	api := fakeIAMUserAPI{user: iamtypes.User{Arn: aws.String(arn), UserName: aws.String("demo"), Path: aws.String("/team/")}}
	rows, err := listIAMUserRecords(context.Background(), api, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil || len(rows) != 1 || rows[0].Resource == nil {
		t.Fatalf("user read: rows=%+v err=%v", rows, err)
	}
	got := rows[0].Resource
	if got.Region != "aws-global" || got.ResourceType != "aws_iam_user" || got.ResourceID != arn || got.SourceRecordID != arn || len(got.CorrelationAnchors) != 2 {
		t.Fatalf("user identity: %+v", got)
	}
	encoded, err := json.Marshal(got.Attributes)
	if err != nil || !strings.Contains(string(encoded), `"attached_policy_arns":null`) || !strings.Contains(string(encoded), `"inline_policy_names":null`) {
		t.Fatalf("legacy nil policy shape: %s err=%v", encoded, err)
	}
}

func TestIAMUserRecordRejectsUnverifiedIdentity(t *testing.T) {
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	for _, arn := range []string{
		"arn:aws:iam:us-east-1:123456789012:user/demo",
		"arn:aws:iam::999999999999:user/demo",
		"arn:aws-us-gov:iam::123456789012:user/demo",
		"arn:aws:iam::123456789012:user/other",
	} {
		listed := iamtypes.User{Arn: aws.String(arn), UserName: aws.String("demo")}
		if _, err := iamUserRecord(listed, nil, nil, nil, "us-east-1", identity); err == nil {
			t.Fatalf("unverified user ARN accepted: %s", arn)
		}
	}
}

func TestIAMUserRecordUsesListedDetailWhenGetUserOmitsIt(t *testing.T) {
	arn := "arn:aws:iam::123456789012:user/demo"
	listed := iamtypes.User{Arn: aws.String(arn), UserName: aws.String("demo"), Path: aws.String("/listed/")}
	row, err := iamUserRecord(listed, nil, nil, nil, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil || row.Resource == nil || row.Resource.Attributes["path"] != "/listed/" {
		t.Fatalf("listed fallback: row=%+v err=%v", row, err)
	}
}
