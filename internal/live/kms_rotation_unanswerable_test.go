// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// loadWave1KMSUnanswerableFixture reads the disabled + pending-import rows.
// It reuses the wave1KMSFixture shape so the shared stub serves them as
// KMS JSON-protocol responses with no stub change.
func loadWave1KMSUnanswerableFixture(t *testing.T) wave1KMSFixture {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/wave1-kms-unanswerable-rotation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture wave1KMSFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

// TestWave1KMSDisabledAndPendingImportSkipRotation drives the full production
// listKMS path over a disabled key and a pending-import key: the service read
// must succeed with rotation_status_known=false and no rotation_enabled
// attribute on either key. Before the gate fix, the rotation call failed the
// whole KMS service read (the stub errors on any rotation query for an
// unanswerable key, so reaching the assertions proves the call was skipped).
func TestWave1KMSDisabledAndPendingImportSkipRotation(t *testing.T) {
	t.Parallel()

	fixture := loadWave1KMSUnanswerableFixture(t)
	cfg := wave1KMSStubConfig(t, fixture)
	records, err := listKMS(context.Background(), cfg, VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatalf("listKMS with disabled/pending-import keys = %v, want success", err)
	}
	byID := map[string]collector.Record{}
	for _, record := range records {
		if record.Resource != nil {
			byID[record.Resource.ResourceID] = record
		}
	}
	for _, id := range []string{
		"e1b2c3d4-e5f6-4789-abcd-ef0123456789",
		"f1b2c3d4-e5f6-4789-abcd-ef0123456789",
	} {
		key, ok := byID[id]
		if !ok {
			t.Fatalf("key %q record missing", id)
		}
		if known := key.Resource.Attributes["rotation_status_known"]; known != false {
			t.Errorf("key %q rotation_status_known = %#v, want false", id, known)
		}
		if value, present := key.Resource.Attributes["rotation_enabled"]; present {
			t.Errorf("key %q rotation_enabled = %#v, want absent", id, value)
		}
	}
}

// stubKMSRotationClient is a kmsDetailAPI fake with a canned rotation answer.
type stubKMSRotationClient struct {
	output *awskms.GetKeyRotationStatusOutput
	err    error
}

func (s stubKMSRotationClient) ListResourceTags(context.Context, *awskms.ListResourceTagsInput, ...func(*awskms.Options)) (*awskms.ListResourceTagsOutput, error) {
	return &awskms.ListResourceTagsOutput{}, nil
}

func (s stubKMSRotationClient) ListKeyPolicies(context.Context, *awskms.ListKeyPoliciesInput, ...func(*awskms.Options)) (*awskms.ListKeyPoliciesOutput, error) {
	return &awskms.ListKeyPoliciesOutput{}, nil
}

func (s stubKMSRotationClient) GetKeyRotationStatus(context.Context, *awskms.GetKeyRotationStatusInput, ...func(*awskms.Options)) (*awskms.GetKeyRotationStatusOutput, error) {
	return s.output, s.err
}

func enabledSymmetricKey(state kmstypes.KeyState) kmstypes.KeyMetadata {
	return kmstypes.KeyMetadata{
		KeyManager: kmstypes.KeyManagerTypeCustomer,
		KeyUsage:   kmstypes.KeyUsageTypeEncryptDecrypt,
		KeySpec:    kmstypes.KeySpecSymmetricDefault,
		KeyState:   state,
	}
}

// TestKMSRotationSupportedSkipsUnanswerableStates pins the gate: disabled and
// pending-import keys never reach the API, alongside the pre-existing skips.
func TestKMSRotationSupportedSkipsUnanswerableStates(t *testing.T) {
	t.Parallel()

	for state, want := range map[kmstypes.KeyState]bool{
		kmstypes.KeyStateEnabled:                true,
		kmstypes.KeyStateDisabled:               false,
		kmstypes.KeyStatePendingImport:          false,
		kmstypes.KeyStatePendingDeletion:        false,
		kmstypes.KeyStatePendingReplicaDeletion: false,
		kmstypes.KeyStateUnavailable:            false,
		kmstypes.KeyStateCreating:               false,
	} {
		if got := kmsRotationSupported(enabledSymmetricKey(state)); got != want {
			t.Errorf("kmsRotationSupported(%q) = %v, want %v", state, got, want)
		}
	}
}

// TestReadKMSRotationToleratesUnanswerableErrors proves the race window: a key
// that passes the gate but cannot answer (disabled, invalid state, or deleted
// between DescribeKey and the rotation call) maps to unknown instead of
// failing the service read, while a real outage error still propagates.
func TestReadKMSRotationToleratesUnanswerableErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	key := enabledSymmetricKey(kmstypes.KeyStateEnabled)
	for _, code := range []string{"DisabledException", "KMSInvalidStateException", "NotFoundException"} {
		rotation, err := readKMSRotation(ctx, stubKMSRotationClient{
			err: &smithy.GenericAPIError{Code: code, Message: "state changed mid-scan"},
		}, "mid-scan-key", key)
		if err != nil {
			t.Errorf("readKMSRotation(%s) error = %v, want unknown", code, err)
		}
		if rotation.known {
			t.Errorf("readKMSRotation(%s) known = true, want false", code)
		}
	}
	if _, err := readKMSRotation(ctx, stubKMSRotationClient{
		err: &smithy.GenericAPIError{Code: "KMSInternalException", Message: "outage"},
	}, "outage-key", key); err == nil {
		t.Error("readKMSRotation(KMSInternalException) error = nil, want propagation")
	}
}
