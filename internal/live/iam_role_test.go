// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
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
	if got.Resource == nil || got.Resource.ResourceType != "aws_iam_role" || got.Resource.ResourceID != arn || got.Resource.ARN != arn || got.Resource.Name != "demo" || got.Resource.Region != "aws-global" {
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

func TestIAMRoleTrustPolicyShapeMatchesLegacy(t *testing.T) {
	arn := "arn:aws:iam::123456789012:role/demo"
	listed := iamtypes.Role{Arn: aws.String(arn), RoleName: aws.String("demo")}
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	for _, raw := range []string{"{}", "%7B%7D", "null", ""} {
		detail := listed
		detail.AssumeRolePolicyDocument = aws.String(raw)
		row, err := iamRoleRecord(listed, &detail, nil, nil, "us-east-1", identity)
		if err != nil {
			t.Fatalf("empty trust %q: %v", raw, err)
		}
		attached, ok := row.Resource.Attributes["attached_policy_arns"].([]string)
		if !ok {
			t.Fatalf("empty trust/list shape %q: attached_policy_arns has unexpected type %T", raw, row.Resource.Attributes["attached_policy_arns"])
		}
		inline, ok := row.Resource.Attributes["inline_policy_names"].([]string)
		if !ok {
			t.Fatalf("empty trust/list shape %q: inline_policy_names has unexpected type %T", raw, row.Resource.Attributes["inline_policy_names"])
		}
		if row.Resource.Attributes["trust_policy_present"] != false || attached != nil || inline != nil {
			t.Fatalf("empty trust/list shape %q: %#v", raw, row.Resource.Attributes)
		}
		encoded, err := json.Marshal(row.Resource.Attributes)
		if err != nil || !strings.Contains(string(encoded), `"attached_policy_arns":null`) || !strings.Contains(string(encoded), `"inline_policy_names":null`) {
			t.Fatalf("empty policy JSON shape %q: %s err=%v", raw, encoded, err)
		}
	}
	detail := listed
	detail.AssumeRolePolicyDocument = aws.String("secret-invalid-{json")
	if _, err := iamRoleRecord(listed, &detail, nil, nil, "us-east-1", identity); err == nil || strings.Contains(err.Error(), "secret-invalid") {
		t.Fatalf("malformed trust must fail without raw value: %v", err)
	}
}

func TestIAMRoleRecordRejectsRegionalARNAndMismatchedName(t *testing.T) {
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	listed := iamtypes.Role{Arn: aws.String("arn:aws:iam::123456789012:role/team/demo"), RoleName: aws.String("demo")}
	for _, test := range []struct {
		name   string
		listed iamtypes.Role
		detail *iamtypes.Role
	}{
		{name: "regional ARN", listed: iamtypes.Role{Arn: aws.String("arn:aws:iam:us-east-1:123456789012:role/team/demo"), RoleName: aws.String("demo")}},
		{name: "wrong ARN suffix", listed: iamtypes.Role{Arn: aws.String("arn:aws:iam::123456789012:role/team/other"), RoleName: aws.String("demo")}},
		{name: "wrong detail name", listed: listed, detail: &iamtypes.Role{Arn: listed.Arn, RoleName: aws.String("other")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := iamRoleRecord(test.listed, test.detail, nil, nil, "us-east-1", identity); err == nil {
				t.Fatal("unbound IAM role identity accepted")
			}
		})
	}
}

func TestCollectReportKeepsIAMRoleGlobalAndS3Regional(t *testing.T) {
	const account = "123456789012"
	const roleARN = "arn:aws:iam::123456789012:role/team/demo"
	const bucketARN = "arn:aws:s3:::assets"
	reader := Collector{
		LoadConfig: func(_ context.Context, region string) (aws.Config, error) { return aws.Config{Region: region}, nil },
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: account, Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{
			"iam": func(ctx context.Context, cfg aws.Config, identity VerifiedIdentity) ([]collector.Record, error) {
				api := &fakeIAMRoleAPI{listed: iamtypes.Role{Arn: aws.String(roleARN), RoleName: aws.String("demo")}}
				return listIAMRoleRecords(ctx, api, cfg.Region, identity)
			},
			"s3": func(_ context.Context, cfg aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
				row := record(bucketARN, "s3", cfg.Region, "assets", "bucket")
				row.Resource = &collector.LiveResource{Region: cfg.Region, ServiceKind: "s3", ResourceType: "aws_s3_bucket", ResourceID: bucketARN, ARN: bucketARN}
				return []collector.Record{row}, nil
			},
		},
	}
	outcome, err := reader.CollectReport(context.Background(), Config{AccountID: account, Regions: []string{"us-east-1"}, Services: []string{"iam", "s3"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Resources) != 2 || outcome.Resources[0].Boundary.Region != "aws-global" || outcome.Resources[0].Boundary.ServiceKind != "iam" || outcome.Resources[1].Boundary.Region != "us-east-1" || outcome.Resources[1].Boundary.ServiceKind != "s3" {
		t.Fatalf("resource boundaries: %+v", outcome.Resources)
	}
	role := outcome.Resources[0]
	role.Boundary.ScopeID = "scope-1"
	role.Boundary.GenerationID = "generation-1"
	role.Boundary.CollectorInstanceID = "aws-cloud-primary"
	role.Boundary.ClaimToken = "fence-1"
	role.Boundary.ObservedAt = time.Now().UTC()
	role.SourceURI = "aws://123456789012"
	globalFact, err := collector.NewResourceFact(role)
	if err != nil {
		t.Fatal(err)
	}
	role.Boundary.Region = "us-east-1"
	regionalFact, err := collector.NewResourceFact(role)
	if err != nil {
		t.Fatal(err)
	}
	if globalFact.Payload["region"] != "aws-global" || globalFact.StableKey == regionalFact.StableKey {
		t.Fatalf("IAM stable key lost global boundary: global=%+v regional=%+v", globalFact, regionalFact)
	}
}
