// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// Live IAM permission documents for the red test: one inline policy with a
// condition value that must never survive normalization, and one managed
// policy document behind the GetPolicy + GetPolicyVersion pair.
const iamPermissionInlineDocument = `{"Version":"2012-10-17","Statement":` +
	`[{"Sid":"InlineRead","Effect":"Allow","Action":"s3:GetObject",` +
	`"Resource":"arn:aws:s3:::assets/*",` +
	`"Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.99"}}}]}`

const iamPermissionManagedDocument = `{"Version":"2012-10-17","Statement":` +
	`[{"Sid":"ManagedWrite","Effect":"Allow","Action":"S3:PutObject",` +
	`"Resource":"arn:aws:s3:::assets/*"}]}`

const iamPermissionManagedARN = "arn:aws:iam::123456789012:policy/assets-write"

// fakeIAMPermissionRoleAPI serves scripted policy documents behind the full
// role read sequence: names/ARNs first, documents only on explicit fetch.
type fakeIAMPermissionRoleAPI struct {
	listed           iamtypes.Role
	detail           *iamtypes.Role
	attached         []string
	inline           []string
	inlineBy         map[string]string
	managed          map[string]string
	denyGet          map[string]bool
	noDefaultVersion map[string]bool
	getCalls         int
}

func (f *fakeIAMPermissionRoleAPI) ListRoles(context.Context, *awsiam.ListRolesInput, ...func(*awsiam.Options)) (*awsiam.ListRolesOutput, error) {
	return &awsiam.ListRolesOutput{Roles: []iamtypes.Role{f.listed}}, nil
}

func (f *fakeIAMPermissionRoleAPI) GetRole(context.Context, *awsiam.GetRoleInput, ...func(*awsiam.Options)) (*awsiam.GetRoleOutput, error) {
	return &awsiam.GetRoleOutput{Role: f.detail}, nil
}

func (f *fakeIAMPermissionRoleAPI) ListAttachedRolePolicies(context.Context, *awsiam.ListAttachedRolePoliciesInput, ...func(*awsiam.Options)) (*awsiam.ListAttachedRolePoliciesOutput, error) {
	out := &awsiam.ListAttachedRolePoliciesOutput{}
	for _, arn := range f.attached {
		out.AttachedPolicies = append(out.AttachedPolicies, iamtypes.AttachedPolicy{PolicyArn: aws.String(arn)})
	}
	return out, nil
}

func (f *fakeIAMPermissionRoleAPI) ListRolePolicies(context.Context, *awsiam.ListRolePoliciesInput, ...func(*awsiam.Options)) (*awsiam.ListRolePoliciesOutput, error) {
	return &awsiam.ListRolePoliciesOutput{PolicyNames: append([]string(nil), f.inline...)}, nil
}

func (f *fakeIAMPermissionRoleAPI) GetRolePolicy(_ context.Context, in *awsiam.GetRolePolicyInput, _ ...func(*awsiam.Options)) (*awsiam.GetRolePolicyOutput, error) {
	if f.denyGet[aws.ToString(in.PolicyName)] {
		return nil, &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}
	}
	return &awsiam.GetRolePolicyOutput{PolicyDocument: aws.String(f.inlineBy[aws.ToString(in.PolicyName)])}, nil
}

func (f *fakeIAMPermissionRoleAPI) GetPolicy(_ context.Context, in *awsiam.GetPolicyInput, _ ...func(*awsiam.Options)) (*awsiam.GetPolicyOutput, error) {
	f.getCalls++
	if f.denyGet[aws.ToString(in.PolicyArn)] {
		return nil, &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}
	}
	if f.noDefaultVersion[aws.ToString(in.PolicyArn)] {
		return &awsiam.GetPolicyOutput{Policy: &iamtypes.Policy{}}, nil
	}
	return &awsiam.GetPolicyOutput{Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v1")}}, nil
}

func (f *fakeIAMPermissionRoleAPI) GetPolicyVersion(_ context.Context, in *awsiam.GetPolicyVersionInput, _ ...func(*awsiam.Options)) (*awsiam.GetPolicyVersionOutput, error) {
	if f.denyGet[aws.ToString(in.PolicyArn)] {
		return nil, &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}
	}
	return &awsiam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(f.managed[aws.ToString(in.PolicyArn)])}}, nil
}

func iamPermissionRoleFixture() *fakeIAMPermissionRoleAPI {
	arn := "arn:aws:iam::123456789012:role/demo"
	role := iamtypes.Role{Arn: aws.String(arn), RoleName: aws.String("demo"), Path: aws.String("/")}
	detail := role
	return &fakeIAMPermissionRoleAPI{
		listed:   role,
		detail:   &detail,
		attached: []string{iamPermissionManagedARN},
		inline:   []string{"inline-read"},
		inlineBy: map[string]string{"inline-read": iamPermissionInlineDocument},
		managed:  map[string]string{iamPermissionManagedARN: iamPermissionManagedDocument},
		denyGet:  map[string]bool{},
	}
}

// TestIAMRoleInlineAndManagedPoliciesYieldPermissionStatements is the TDD
// anchor: a role with one inline and one managed policy must yield two
// normalized permission-statement observations, with actions lowercased,
// condition keys kept, and condition values dropped.
func TestIAMRoleInlineAndManagedPoliciesYieldPermissionStatements(t *testing.T) {
	t.Parallel()

	rows, err := listIAMRoleRecords(context.Background(), iamPermissionRoleFixture(), "us-east-1",
		VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	got := rows[0].IAMPermissionStatements
	if len(got) != 2 {
		t.Fatalf("permission statements = %+v, want 1 inline + 1 managed", got)
	}
	bySource := map[string]collector.IAMPermissionObservation{}
	for _, statement := range got {
		bySource[statement.PolicySource] = statement
	}
	inline, ok := bySource["inline"]
	// Observations keep the document's raw action casing (mirroring the
	// in-tree PolicyStatement); the envelope lowercases at fact build.
	if !ok || inline.PolicyName != "inline-read" || !reflect.DeepEqual(inline.Actions, []string{"s3:GetObject"}) {
		t.Fatalf("inline statement = %+v", inline)
	}
	if !reflect.DeepEqual(inline.ConditionKeys, []string{"aws:SourceIp"}) {
		t.Fatalf("inline condition keys = %+v, want keys only", inline.ConditionKeys)
	}
	if inline.PrincipalARN != "arn:aws:iam::123456789012:role/demo" || inline.PrincipalType != "aws_iam_role" {
		t.Fatalf("inline principal binding = %+v", inline)
	}
	managed, ok := bySource["attached_managed"]
	if !ok || managed.PolicyARN != iamPermissionManagedARN || !reflect.DeepEqual(managed.Actions, []string{"S3:PutObject"}) {
		t.Fatalf("managed statement = %+v", managed)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	// Statement SIDs and action/resource patterns are evidence by design;
	// condition values and document syntax must never survive.
	for _, leaked := range []string{"192.0.2.99", "PolicyDocument", `"Version"`, `"Statement"`} {
		if strings.Contains(string(encoded), leaked) {
			t.Fatalf("raw document text %q leaked into observations: %s", leaked, encoded)
		}
	}
	// The derived observations must feed the emitted fact builder end to end.
	for _, statement := range got {
		statement.Boundary.AccountID = "123456789012"
		statement.Boundary.ScopeID = "scope-1"
		statement.Boundary.GenerationID = "generation-1"
		statement.Boundary.CollectorInstanceID = "aws-cloud-primary"
		statement.Boundary.ClaimToken = "fence-1"
		statement.Boundary.ObservedAt = time.Now().UTC()
		statement.SourceURI = "aws:iam:role/demo"
		fact, err := collector.NewIAMPermissionFact(statement)
		if err != nil {
			t.Fatal(err)
		}
		if fact.Kind != collector.AWSKindIAMPermission {
			t.Fatalf("fact kind = %q", fact.Kind)
		}
		actions, ok := fact.Payload["actions"].([]string)
		if !ok {
			t.Fatalf("fact actions = %#v, want string list", fact.Payload["actions"])
		}
		want := map[string]string{"inline-read": "s3:getobject", "": "s3:putobject"}[statement.PolicyName]
		if len(actions) != 1 || actions[0] != want {
			t.Fatalf("fact actions = %q, want normalized %q", actions, want)
		}
	}
}

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

// TestIAMRoleTrustAndBoundaryYieldPermissionStatements pins the remaining
// sources: the trust document normalizes to a trust statement carrying the
// assume principals, and the permission-boundary policy normalizes with the
// boundary source.
func TestIAMRoleTrustAndBoundaryYieldPermissionStatements(t *testing.T) {
	t.Parallel()

	const trustDocument = `{"Version":"2012-10-17","Statement":` +
		`[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},` +
		`"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`
	const boundaryARN = "arn:aws:iam::123456789012:policy/boundary"
	const boundaryDocument = `{"Version":"2012-10-17","Statement":` +
		`[{"Sid":"BoundaryCap","Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`
	api := iamPermissionRoleFixture()
	api.inline = nil
	api.inlineBy = map[string]string{}
	api.attached = nil
	detail := *api.detail
	detail.AssumeRolePolicyDocument = aws.String(trustDocument)
	detail.PermissionsBoundary = &iamtypes.AttachedPermissionsBoundary{PermissionsBoundaryArn: aws.String(boundaryARN)}
	api.detail = &detail
	api.managed = map[string]string{boundaryARN: boundaryDocument}
	rows, err := listIAMRoleRecords(context.Background(), api, "us-east-1",
		VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || len(rows[0].IAMPermissionStatements) != 2 {
		t.Fatalf("statements = %+v, want trust + boundary", rows[0].IAMPermissionStatements)
	}
	bySource := map[string]collector.IAMPermissionObservation{}
	for _, statement := range rows[0].IAMPermissionStatements {
		bySource[statement.PolicySource] = statement
	}
	trust, ok := bySource["trust"]
	if !ok || !reflect.DeepEqual(trust.AssumePrincipals, []string{"arn:aws:iam::123456789012:root"}) {
		t.Fatalf("trust statement = %+v", trust)
	}
	if !reflect.DeepEqual(trust.ConditionKeys, []string{"aws:SecureTransport"}) {
		t.Fatalf("trust condition keys = %+v", trust.ConditionKeys)
	}
	if trust.PolicyARN != "" || trust.PolicyName != "" {
		t.Fatalf("trust must not name a policy: %+v", trust)
	}
	boundary, ok := bySource["permission_boundary"]
	if !ok || boundary.PolicyARN != boundaryARN || !reflect.DeepEqual(boundary.Actions, []string{"s3:ListBucket"}) {
		t.Fatalf("boundary statement = %+v", boundary)
	}
}

// fakeIAMPermissionUserAPI serves scripted user documents.
type fakeIAMPermissionUserAPI struct {
	user    iamtypes.User
	inline  []string
	byName  map[string]string
	byARN   map[string]string
	denyGet map[string]bool
}

func (f *fakeIAMPermissionUserAPI) ListUsers(context.Context, *awsiam.ListUsersInput, ...func(*awsiam.Options)) (*awsiam.ListUsersOutput, error) {
	return &awsiam.ListUsersOutput{Users: []iamtypes.User{f.user}}, nil
}

func (f *fakeIAMPermissionUserAPI) GetUser(context.Context, *awsiam.GetUserInput, ...func(*awsiam.Options)) (*awsiam.GetUserOutput, error) {
	return &awsiam.GetUserOutput{User: &f.user}, nil
}

func (f *fakeIAMPermissionUserAPI) ListAttachedUserPolicies(context.Context, *awsiam.ListAttachedUserPoliciesInput, ...func(*awsiam.Options)) (*awsiam.ListAttachedUserPoliciesOutput, error) {
	return &awsiam.ListAttachedUserPoliciesOutput{AttachedPolicies: []iamtypes.AttachedPolicy{{PolicyArn: aws.String(iamPermissionManagedARN)}}}, nil
}

func (f *fakeIAMPermissionUserAPI) ListUserPolicies(context.Context, *awsiam.ListUserPoliciesInput, ...func(*awsiam.Options)) (*awsiam.ListUserPoliciesOutput, error) {
	return &awsiam.ListUserPoliciesOutput{PolicyNames: append([]string(nil), f.inline...)}, nil
}

func (f *fakeIAMPermissionUserAPI) GetUserPolicy(_ context.Context, in *awsiam.GetUserPolicyInput, _ ...func(*awsiam.Options)) (*awsiam.GetUserPolicyOutput, error) {
	if f.denyGet[aws.ToString(in.PolicyName)] {
		return nil, &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}
	}
	return &awsiam.GetUserPolicyOutput{PolicyDocument: aws.String(f.byName[aws.ToString(in.PolicyName)])}, nil
}

func (f *fakeIAMPermissionUserAPI) GetPolicy(_ context.Context, in *awsiam.GetPolicyInput, _ ...func(*awsiam.Options)) (*awsiam.GetPolicyOutput, error) {
	return &awsiam.GetPolicyOutput{Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v1")}}, nil
}

func (f *fakeIAMPermissionUserAPI) GetPolicyVersion(_ context.Context, in *awsiam.GetPolicyVersionInput, _ ...func(*awsiam.Options)) (*awsiam.GetPolicyVersionOutput, error) {
	return &awsiam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(f.byARN[aws.ToString(in.PolicyArn)])}}, nil
}

// TestIAMUserInlineAndManagedPoliciesYieldPermissionStatements covers the
// user reader: same document kinds, user principal binding.
func TestIAMUserInlineAndManagedPoliciesYieldPermissionStatements(t *testing.T) {
	t.Parallel()

	arn := "arn:aws:iam::123456789012:user/deploy"
	api := &fakeIAMPermissionUserAPI{
		user:    iamtypes.User{Arn: aws.String(arn), UserName: aws.String("deploy"), Path: aws.String("/")},
		inline:  []string{"inline-deploy"},
		byName:  map[string]string{"inline-deploy": iamPermissionInlineDocument},
		byARN:   map[string]string{iamPermissionManagedARN: iamPermissionManagedDocument},
		denyGet: map[string]bool{},
	}
	rows, err := listIAMUserRecords(context.Background(), api, "us-east-1",
		VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || len(rows[0].IAMPermissionStatements) != 2 {
		t.Fatalf("statements = %+v, want 1 inline + 1 managed", rows[0].IAMPermissionStatements)
	}
	for _, statement := range rows[0].IAMPermissionStatements {
		if statement.PrincipalARN != arn || statement.PrincipalType != "aws_iam_user" {
			t.Fatalf("user principal binding = %+v", statement)
		}
		if statement.Boundary.Region != "aws-global" || statement.Boundary.ServiceKind != "iam" {
			t.Fatalf("statement boundary = %+v", statement.Boundary)
		}
	}
}

// TestCollectReportCarriesIAMPermissions proves the fan-out wiring: record
// statements flow through CollectReport into Outcome.IAMPermissions and
// through the shared AppendOutcomeFacts into validated aws_iam_permission
// facts. Dropping the family from either seam fails here instead of silently
// emitting zero permission facts in production.
func TestCollectReportCarriesIAMPermissions(t *testing.T) {
	t.Parallel()

	statement := collector.IAMPermissionObservation{
		Boundary:      collector.Boundary{Region: "aws-global", ServiceKind: "iam"},
		PrincipalARN:  "arn:aws:iam::123456789012:role/demo",
		PrincipalType: "aws_iam_role",
		PolicySource:  "inline",
		PolicyName:    "inline-read",
		StatementSID:  "InlineRead",
		Effect:        "Allow",
		Actions:       []string{"s3:GetObject"},
		Resources:     []string{"arn:aws:s3:::assets/*"},
	}
	c := Collector{
		LoadConfig: fakeConfig(&[]string{}), VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{"iam": func(_ context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
			return []collector.Record{{IAMPermissionStatements: []collector.IAMPermissionObservation{statement}}}, nil
		}},
	}
	outcome, err := c.CollectReport(context.Background(), Config{
		AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"iam"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.IAMPermissions) != 1 || outcome.IAMPermissions[0].Boundary.AccountID != "123456789012" {
		t.Fatalf("IAMPermissions = %+v", outcome.IAMPermissions)
	}
	observedAt := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	result := sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultComplete,
		Claim: sdk.Claim{
			ComponentID: collector.ComponentID, InstanceID: "aws-parity-iam",
			CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem,
			Scope:       sdk.Scope{ID: "aws:123456789012:us-east-1", Kind: "component"},
			SourceRunID: "iam-parity-run", GenerationID: "aws:123456789012:us-east-1:iam:1",
			WorkItemID: "iam-parity-work", FencingToken: "iam-parity-token",
			Attempt: 1, Deadline: observedAt.Add(time.Hour), ConfigHandle: "component-config:aws-cloud",
		},
		Generation: sdk.Generation{ID: "aws:123456789012:us-east-1:iam:1", ObservedAt: observedAt},
	}
	if result, err = AppendOutcomeFacts(result, outcome, "aws:iam:us-east-1:iam-parity", collector.DefaultResourceUse()); err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.NewValidator(collector.Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected pipeline result carrying permission facts: %v", err)
	}
	found := false
	for _, fact := range result.Facts {
		if fact.Kind == collector.AWSKindIAMPermission {
			found = true
		}
	}
	if !found {
		t.Fatalf("pipeline result missing aws_iam_permission fact: %+v", result.Facts)
	}
}

// TestIAMPermissionStatementsDeterministicAcrossReads pins retry
// idempotency: two reads of the same documents yield identical observations.
func TestIAMPermissionStatementsDeterministicAcrossReads(t *testing.T) {
	t.Parallel()

	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	first, err := listIAMRoleRecords(context.Background(), iamPermissionRoleFixture(), "us-east-1", identity)
	if err != nil {
		t.Fatal(err)
	}
	second, err := listIAMRoleRecords(context.Background(), iamPermissionRoleFixture(), "us-east-1", identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("rows = %d/%d, want 1/1", len(first), len(second))
	}
	if !reflect.DeepEqual(first[0].IAMPermissionStatements, second[0].IAMPermissionStatements) {
		t.Fatalf("retry changed statements:\nfirst=%+v\nsecond=%+v", first[0].IAMPermissionStatements, second[0].IAMPermissionStatements)
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
