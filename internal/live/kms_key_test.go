// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type fakeKMSKeys struct {
	listed    int
	described []string
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
	return &awskms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyId: aws.String("key-1"), Arn: aws.String("arn:aws:kms:us-east-1:123456789012:key/key-1"), KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled}}, nil
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
			if _, err := kmsKeyRecord(key, "key-1", "us-east-1", identity); err == nil {
				t.Fatal("unsafe reported identity accepted")
			}
		})
	}
}
