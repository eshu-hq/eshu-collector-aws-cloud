// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

type fakeKMSKeys struct {
	listed    int
	described []string
	aliasErr  error
	grantErr  error

	metadata      *kmstypes.KeyMetadata
	tags          map[string]string
	tagsErr       error
	policyNames   []string
	policyErr     error
	rotation      bool
	rotationErr   error
	rotationCalls []string
}

func (f *fakeKMSKeys) ListKeys(_ context.Context, input *awskms.ListKeysInput, _ ...func(*awskms.Options)) (*awskms.ListKeysOutput, error) {
	f.listed++
	if f.listed == 1 {
		return &awskms.ListKeysOutput{Keys: []kmstypes.KeyListEntry{{KeyId: aws.String("key-1")}}, Truncated: true, NextMarker: aws.String("next")}, nil
	}
	if aws.ToString(input.Marker) != "next" {
		panic("unexpected marker")
	}
	return &awskms.ListKeysOutput{}, nil
}

func (f *fakeKMSKeys) DescribeKey(_ context.Context, input *awskms.DescribeKeyInput, _ ...func(*awskms.Options)) (*awskms.DescribeKeyOutput, error) {
	f.described = append(f.described, aws.ToString(input.KeyId))
	if f.metadata != nil {
		return &awskms.DescribeKeyOutput{KeyMetadata: f.metadata}, nil
	}
	return &awskms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String("key-1"), Arn: aws.String("arn:aws:kms:us-east-1:123456789012:key/key-1"), KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled}}, nil
}

func (f *fakeKMSKeys) ListResourceTags(context.Context, *awskms.ListResourceTagsInput, ...func(*awskms.Options)) (*awskms.ListResourceTagsOutput, error) {
	if f.tagsErr != nil {
		return nil, f.tagsErr
	}
	output := &awskms.ListResourceTagsOutput{}
	for key, value := range f.tags {
		output.Tags = append(output.Tags, kmstypes.Tag{TagKey: aws.String(key), TagValue: aws.String(value)})
	}
	return output, nil
}

func (f *fakeKMSKeys) GetKeyRotationStatus(ctx context.Context, input *awskms.GetKeyRotationStatusInput, _ ...func(*awskms.Options)) (*awskms.GetKeyRotationStatusOutput, error) {
	f.rotationCalls = append(f.rotationCalls, aws.ToString(input.KeyId))
	if f.rotationErr != nil {
		return nil, f.rotationErr
	}
	return &awskms.GetKeyRotationStatusOutput{KeyRotationEnabled: f.rotation}, nil
}

func (f *fakeKMSKeys) ListKeyPolicies(context.Context, *awskms.ListKeyPoliciesInput, ...func(*awskms.Options)) (*awskms.ListKeyPoliciesOutput, error) {
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	return &awskms.ListKeyPoliciesOutput{PolicyNames: append([]string(nil), f.policyNames...)}, nil
}

// rotationSupportedKMSMetadata mirrors a customer-managed symmetric
// encrypt/decrypt key in service: the only shape AWS answers rotation status
// for.
func rotationSupportedKMSMetadata() *kmstypes.KeyMetadata {
	return &kmstypes.KeyMetadata{
		KeyId: aws.String("key-1"), Arn: aws.String("arn:aws:kms:us-east-1:123456789012:key/key-1"),
		KeyManager: kmstypes.KeyManagerTypeCustomer, KeyUsage: kmstypes.KeyUsageTypeEncryptDecrypt,
		KeySpec: kmstypes.KeySpecSymmetricDefault, KeyState: kmstypes.KeyStateEnabled,
	}
}

func (f *fakeKMSKeys) ListAliases(context.Context, *awskms.ListAliasesInput, ...func(*awskms.Options)) (*awskms.ListAliasesOutput, error) {
	if f.aliasErr != nil {
		return nil, f.aliasErr
	}
	return &awskms.ListAliasesOutput{}, nil
}

func (f *fakeKMSKeys) ListGrants(context.Context, *awskms.ListGrantsInput, ...func(*awskms.Options)) (*awskms.ListGrantsOutput, error) {
	if f.grantErr != nil {
		return nil, f.grantErr
	}
	return &awskms.ListGrantsOutput{}, nil
}

func TestKMSKeyLoaderEmitsReportedIdentity(t *testing.T) {
	client := &fakeKMSKeys{}
	rows, err := listKMSWithAPI(context.Background(), client, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Resource == nil {
		t.Fatalf("rows = %#v", rows)
	}
	r := rows[0].Resource
	if r.ResourceType != "aws_kms_key" || r.ResourceID != "key-1" || r.ARN != "arn:aws:kms:us-east-1:123456789012:key/key-1" || r.Attributes["key_manager"] != "CUSTOMER" {
		t.Fatalf("resource = %#v", r)
	}
	if client.listed != 2 || len(client.described) != 1 || client.described[0] != "key-1" {
		t.Fatalf("API calls: %+v", client)
	}
}

func TestKMSKeyRejectsForeignOrMissingReportedIdentity(t *testing.T) {
	base := kmstypes.KeyMetadata{KeyId: aws.String("key-1"), Arn: aws.String("arn:aws:kms:us-east-1:123456789012:key/key-1")}
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	cases := []struct {
		name   string
		mutate func(*kmstypes.KeyMetadata)
	}{
		{"missing ARN", func(k *kmstypes.KeyMetadata) { k.Arn = nil }},
		{"wrong key", func(k *kmstypes.KeyMetadata) { k.KeyId = aws.String("key-2") }},
		{"wrong account", func(k *kmstypes.KeyMetadata) { k.Arn = aws.String("arn:aws:kms:us-east-1:999999999999:key/key-1") }},
		{"wrong region", func(k *kmstypes.KeyMetadata) { k.Arn = aws.String("arn:aws:kms:us-west-2:123456789012:key/key-1") }},
		{"wrong partition", func(k *kmstypes.KeyMetadata) { k.Arn = aws.String("arn:aws-cn:kms:us-east-1:123456789012:key/key-1") }},
		{"alias ARN", func(k *kmstypes.KeyMetadata) { k.Arn = aws.String("arn:aws:kms:us-east-1:123456789012:alias/key-1") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := base
			tc.mutate(&key)
			if _, err := kmsKeyRecord(key, "key-1", "us-east-1", identity, kmsKeyDetail{}); err == nil {
				t.Fatal("unsafe reported identity accepted")
			}
		})
	}
}

func TestKMSAliasOrGrantReadFailureFailsService(t *testing.T) {
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	denied := errors.New("access denied")
	if _, err := listKMSWithAPI(context.Background(), &fakeKMSKeys{aliasErr: denied}, "us-east-1", identity); err == nil {
		t.Fatal("alias list failure accepted")
	}
	if _, err := listKMSWithAPI(context.Background(), &fakeKMSKeys{grantErr: denied}, "us-east-1", identity); err == nil {
		t.Fatal("grant list failure accepted")
	}
}

func TestKMSKeyEnrichmentEmitsTagsRotationAndPolicyNames(t *testing.T) {
	client := &fakeKMSKeys{
		metadata:    rotationSupportedKMSMetadata(),
		tags:        map[string]string{"env": "wave1", "team": "keys"},
		policyNames: []string{"default"},
		rotation:    true,
	}
	rows, err := listKMSWithAPI(context.Background(), client, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Resource == nil {
		t.Fatalf("rows = %#v", rows)
	}
	r := rows[0].Resource
	if !reflect.DeepEqual(r.Tags, map[string]string{"env": "wave1", "team": "keys"}) {
		t.Fatalf("tags = %#v", r.Tags)
	}
	if !reflect.DeepEqual(r.Attributes["policy_revision_names"], []string{"default"}) {
		t.Fatalf("policy_revision_names = %#v", r.Attributes["policy_revision_names"])
	}
	if r.Attributes["rotation_status_known"] != true || r.Attributes["rotation_enabled"] != true {
		t.Fatalf("rotation attributes = %#v", r.Attributes)
	}
	if r.Attributes["alias_count"] != 0 || r.Attributes["grant_count"] != 0 {
		t.Fatalf("counts = %#v", r.Attributes)
	}
	if len(client.rotationCalls) != 1 || client.rotationCalls[0] != "key-1" {
		t.Fatalf("rotation calls = %#v", client.rotationCalls)
	}
}

func TestKMSKeyRotationUnsupportedKeysStayUnknown(t *testing.T) {
	base := rotationSupportedKMSMetadata()
	cases := []struct {
		name   string
		mutate func(*kmstypes.KeyMetadata)
	}{
		{"aws managed", func(k *kmstypes.KeyMetadata) { k.KeyManager = kmstypes.KeyManagerTypeAws }},
		{"sign verify", func(k *kmstypes.KeyMetadata) {
			k.KeyUsage = kmstypes.KeyUsageTypeSignVerify
			k.KeySpec = kmstypes.KeySpecRsa2048
		}},
		{"hmac", func(k *kmstypes.KeyMetadata) {
			k.KeyUsage = kmstypes.KeyUsageTypeGenerateVerifyMac
			k.KeySpec = kmstypes.KeySpecHmac256
		}},
		{"pending deletion", func(k *kmstypes.KeyMetadata) { k.KeyState = kmstypes.KeyStatePendingDeletion }},
		{"pending replica deletion", func(k *kmstypes.KeyMetadata) { k.KeyState = kmstypes.KeyStatePendingReplicaDeletion }},
		{"unavailable", func(k *kmstypes.KeyMetadata) { k.KeyState = kmstypes.KeyStateUnavailable }},
		{"creating", func(k *kmstypes.KeyMetadata) { k.KeyState = kmstypes.KeyStateCreating }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := *base
			tc.mutate(&metadata)
			client := &fakeKMSKeys{metadata: &metadata, rotation: true}
			rows, err := listKMSWithAPI(context.Background(), client, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0].Resource == nil {
				t.Fatalf("rows = %#v", rows)
			}
			attrs := rows[0].Resource.Attributes
			if attrs["rotation_status_known"] != false {
				t.Fatalf("rotation_status_known = %#v, want false (no rotation read)", attrs["rotation_status_known"])
			}
			if _, ok := attrs["rotation_enabled"]; ok {
				t.Fatalf("rotation_enabled present = %#v, want absent", attrs["rotation_enabled"])
			}
			if len(client.rotationCalls) != 0 {
				t.Fatalf("rotation calls = %#v, want none", client.rotationCalls)
			}
		})
	}
}

func TestKMSKeyRotationDeniedStaysUnknown(t *testing.T) {
	for _, code := range []string{"AccessDenied", "AccessDeniedException", "UnsupportedOperationException", "UnsupportedOperation"} {
		err := &smithy.GenericAPIError{Code: code, Message: "denied"}
		client := &fakeKMSKeys{metadata: rotationSupportedKMSMetadata(), rotationErr: err}
		rows, listErr := listKMSWithAPI(context.Background(), client, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
		if listErr != nil {
			t.Fatalf("rotation %v failed the service: %v", err, listErr)
		}
		if rows[0].Resource.Attributes["rotation_status_known"] != false {
			t.Fatalf("rotation_status_known = %#v, want false", rows[0].Resource.Attributes["rotation_status_known"])
		}
	}
}

func TestKMSKeyRotationFailureFailsService(t *testing.T) {
	client := &fakeKMSKeys{metadata: rotationSupportedKMSMetadata(), rotationErr: errors.New("expired credentials")}
	if _, err := listKMSWithAPI(context.Background(), client, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}); err == nil {
		t.Fatal("rotation outage accepted as unknown")
	}
}

func TestKMSKeyTagsDeniedRetainsKeyWithNilTags(t *testing.T) {
	for _, code := range []string{"AccessDenied", "AccessDeniedException"} {
		denied := &smithy.GenericAPIError{Code: code, Message: "denied"}
		client := &fakeKMSKeys{metadata: rotationSupportedKMSMetadata(), tagsErr: denied}
		rows, err := listKMSWithAPI(context.Background(), client, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
		if err != nil {
			t.Fatalf("denied tag read (%s) failed the service: %v", code, err)
		}
		if len(rows) != 1 || rows[0].Resource == nil {
			t.Fatalf("rows = %#v", rows)
		}
		if rows[0].Resource.Tags != nil {
			t.Fatalf("tags = %#v, want nil on denial (%s)", rows[0].Resource.Tags, code)
		}
	}
}

func TestKMSKeyPolicyListFailureFailsService(t *testing.T) {
	client := &fakeKMSKeys{policyErr: errors.New("outage")}
	if _, err := listKMSWithAPI(context.Background(), client, "us-east-1", VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}); err == nil {
		t.Fatal("policy name list failure accepted")
	}
}

func TestKMSRotationSupportGate(t *testing.T) {
	supported := rotationSupportedKMSMetadata()
	if !kmsRotationSupported(*supported) {
		t.Fatal("customer symmetric encrypt/decrypt key in service must support rotation checks")
	}
	cases := []struct {
		name   string
		mutate func(*kmstypes.KeyMetadata)
	}{
		{"aws managed", func(k *kmstypes.KeyMetadata) { k.KeyManager = kmstypes.KeyManagerTypeAws }},
		{"sign verify usage", func(k *kmstypes.KeyMetadata) { k.KeyUsage = kmstypes.KeyUsageTypeSignVerify }},
		{"hmac spec", func(k *kmstypes.KeyMetadata) { k.KeySpec = kmstypes.KeySpecHmac256 }},
		{"pending deletion", func(k *kmstypes.KeyMetadata) { k.KeyState = kmstypes.KeyStatePendingDeletion }},
		{"pending replica deletion", func(k *kmstypes.KeyMetadata) { k.KeyState = kmstypes.KeyStatePendingReplicaDeletion }},
		{"unavailable", func(k *kmstypes.KeyMetadata) { k.KeyState = kmstypes.KeyStateUnavailable }},
		{"creating", func(k *kmstypes.KeyMetadata) { k.KeyState = kmstypes.KeyStateCreating }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := *supported
			tc.mutate(&key)
			if kmsRotationSupported(key) {
				t.Fatal("rotation check must be skipped for this key shape")
			}
		})
	}
}

func TestKMSAlgorithmListsPreserveLegacyEmptyShape(t *testing.T) {
	tests := []struct {
		name, expected                    string
		nilResult, emptyResult, populated []string
	}{
		{"encryption", string(kmstypes.EncryptionAlgorithmSpecSymmetricDefault), kmsAlgorithms(nil), kmsAlgorithms([]kmstypes.EncryptionAlgorithmSpec{}), kmsAlgorithms([]kmstypes.EncryptionAlgorithmSpec{kmstypes.EncryptionAlgorithmSpecSymmetricDefault})},
		{"signing", string(kmstypes.SigningAlgorithmSpecRsassaPssSha256), kmsSigningAlgorithms(nil), kmsSigningAlgorithms([]kmstypes.SigningAlgorithmSpec{}), kmsSigningAlgorithms([]kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecRsassaPssSha256})},
		{"MAC", string(kmstypes.MacAlgorithmSpecHmacSha256), kmsMACAlgorithms(nil), kmsMACAlgorithms([]kmstypes.MacAlgorithmSpec{}), kmsMACAlgorithms([]kmstypes.MacAlgorithmSpec{kmstypes.MacAlgorithmSpecHmacSha256})},
		{"agreement", string(kmstypes.KeyAgreementAlgorithmSpecEcdh), kmsAgreementAlgorithms(nil), kmsAgreementAlgorithms([]kmstypes.KeyAgreementAlgorithmSpec{}), kmsAgreementAlgorithms([]kmstypes.KeyAgreementAlgorithmSpec{kmstypes.KeyAgreementAlgorithmSpecEcdh})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.nilResult != nil || tc.emptyResult != nil {
				t.Fatalf("empty lists must be nil: %#v %#v", tc.nilResult, tc.emptyResult)
			}
			if len(tc.populated) != 1 || tc.populated[0] != tc.expected {
				t.Fatalf("populated list = %#v", tc.populated)
			}
		})
	}
}
