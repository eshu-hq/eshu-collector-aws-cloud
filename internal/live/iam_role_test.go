// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func TestIAMRoleRecordUsesVerifiedIdentityAndSafeMetadata(t *testing.T) {
	arn := "arn:aws:iam::123456789012:role/team/demo"
	listed := iamtypes.Role{Arn: aws.String(arn), RoleName: aws.String("demo"), Path: aws.String("/team/")}
	detail := listed
	detail.AssumeRolePolicyDocument = aws.String(`{"Statement":[{"Principal":{"AWS":"secret-principal"}}]}`)
	got, err := iamRoleRecord(listed, &detail, []string{"arn:aws:iam::123456789012:policy/read"}, []string{"inline-read"}, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Resource == nil || got.Resource.ResourceType != "aws_iam_role" || got.Resource.ResourceID != arn || got.Resource.ARN != arn || got.Resource.Name != "demo" {
		t.Fatalf("role identity = %+v", got.Resource)
	}
	if got.Resource.Attributes["path"] != "/team/" || got.Resource.Attributes["trust_policy_present"] != true || got.Resource.Attributes["attached_policy_arns"] == nil || got.Resource.Attributes["inline_policy_names"] == nil {
		t.Fatalf("role attributes = %#v", got.Resource.Attributes)
	}
	encoded, err := json.Marshal(got.Resource)
	if err != nil || strings.Contains(string(encoded), "secret-principal") {
		t.Fatalf("raw trust content escaped into emitted resource: %s err=%v", encoded, err)
	}
	if got.Resource.SourceRecordID != arn || len(got.Resource.CorrelationAnchors) != 2 {
		t.Fatalf("role provenance = %+v", got.Resource)
	}
	if _, err := iamRoleRecord(listed, &detail, nil, nil, "us-east-1", VerifiedIdentity{AccountID: "999999999999", Partition: "aws"}); err == nil {
		t.Fatal("foreign account role accepted")
	}
	if _, err := iamRoleRecord(listed, &detail, nil, nil, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws-us-gov"}); err == nil {
		t.Fatal("foreign partition role accepted")
	}
}

type fakeIAMRoleAPI struct {
	listed      iamtypes.Role
	detail      *iamtypes.Role
	getErr      error
	attachedErr error
	calls       []string
}

func (f *fakeIAMRoleAPI) ListRoles(_ context.Context, _ *awsiam.ListRolesInput, _ ...func(*awsiam.Options)) (*awsiam.ListRolesOutput, error) {
	f.calls = append(f.calls, "ListRoles")
	return &awsiam.ListRolesOutput{Roles: []iamtypes.Role{f.listed}}, nil
}
func (f *fakeIAMRoleAPI) GetRole(_ context.Context, _ *awsiam.GetRoleInput, _ ...func(*awsiam.Options)) (*awsiam.GetRoleOutput, error) {
	f.calls = append(f.calls, "GetRole")
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &awsiam.GetRoleOutput{Role: f.detail}, nil
}
func (f *fakeIAMRoleAPI) ListAttachedRolePolicies(_ context.Context, _ *awsiam.ListAttachedRolePoliciesInput, _ ...func(*awsiam.Options)) (*awsiam.ListAttachedRolePoliciesOutput, error) {
	f.calls = append(f.calls, "ListAttachedRolePolicies")
	if f.attachedErr != nil {
		return nil, f.attachedErr
	}
	return &awsiam.ListAttachedRolePoliciesOutput{AttachedPolicies: []iamtypes.AttachedPolicy{{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/read")}}}, nil
}
func (f *fakeIAMRoleAPI) ListRolePolicies(_ context.Context, _ *awsiam.ListRolePoliciesInput, _ ...func(*awsiam.Options)) (*awsiam.ListRolePoliciesOutput, error) {
	f.calls = append(f.calls, "ListRolePolicies")
	return &awsiam.ListRolePoliciesOutput{PolicyNames: []string{"inline-read"}}, nil
}

func TestIAMRoleReadMissingDetailAndDenial(t *testing.T) {
	arn := "arn:aws:iam::123456789012:role/demo"
	listed := iamtypes.Role{Arn: aws.String(arn), RoleName: aws.String("demo"), Path: aws.String("/listed/")}
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	client := &fakeIAMRoleAPI{listed: listed}
	rows, err := listIAMRoleRecords(context.Background(), client, "us-east-1", identity)
	if err != nil || len(rows) != 1 || rows[0].Resource == nil || rows[0].Resource.Attributes["path"] != "/listed/" {
		t.Fatalf("missing detail must retain listed metadata: rows=%+v err=%v", rows, err)
	}
	if len(client.calls) != 4 {
		t.Fatalf("read sequence = %v", client.calls)
	}
	client.getErr = errors.New("AccessDenied")
	if rows, err := listIAMRoleRecords(context.Background(), client, "us-east-1", identity); err == nil || len(rows) != 0 {
		t.Fatalf("GetRole denial must fail scan: rows=%v err=%v", rows, err)
	}
	client.getErr = nil
	client.attachedErr = errors.New("AccessDenied")
	if rows, err := listIAMRoleRecords(context.Background(), client, "us-east-1", identity); err == nil || len(rows) != 0 {
		t.Fatalf("policy-name denial must fail scan: rows=%v err=%v", rows, err)
	}
}
