// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

// kmsDetailAPI carries the per-key metadata reads beyond DescribeKey: tags,
// policy revision names, and rotation status. Key-policy documents, aliases,
// and grants live on the key slice; cryptographic and lifecycle-mutation calls
// are never part of this contract.
type kmsDetailAPI interface {
	ListResourceTags(context.Context, *awskms.ListResourceTagsInput, ...func(*awskms.Options)) (*awskms.ListResourceTagsOutput, error)
	ListKeyPolicies(context.Context, *awskms.ListKeyPoliciesInput, ...func(*awskms.Options)) (*awskms.ListKeyPoliciesOutput, error)
	GetKeyRotationStatus(context.Context, *awskms.GetKeyRotationStatusInput, ...func(*awskms.Options)) (*awskms.GetKeyRotationStatusOutput, error)
}

// kmsKeyDetail carries the per-key enrichment reads into the key record:
// tags, policy revision names, the joined alias/grant counts, and the
// resolved rotation answer.
type kmsKeyDetail struct {
	Tags        map[string]string
	PolicyNames []string
	AliasCount  int
	GrantCount  int
	Rotation    kmsRotation
}

// kmsRotation carries the resolved automatic-rotation answer for one key.
// known is false when GetKeyRotationStatus is not meaningful for the key
// shape or when AWS reports UnsupportedOperation/AccessDenied; any other
// rotation failure fails the service read so a real outage never masquerades
// as "rotation unknown".
type kmsRotation struct {
	known   bool
	enabled bool
}

// readKMSTags follows every ListResourceTags page for one key. A denied tag
// read contributes no tags, mirroring the in-tree adapter, so it cannot be
// mistaken for an untagged key; any other failure fails the service read.
func readKMSTags(ctx context.Context, client kmsDetailAPI, keyID string) (map[string]string, error) {
	tags := map[string]string{}
	pages := awskms.NewListResourceTagsPaginator(client, &awskms.ListResourceTagsInput{KeyId: aws.String(keyID)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			if kmsIsDenied(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("kms list resource tags: %w", err)
		}
		if page == nil {
			continue
		}
		for _, tag := range page.Tags {
			key := strings.TrimSpace(aws.ToString(tag.TagKey))
			if key == "" {
				continue
			}
			tags[key] = aws.ToString(tag.TagValue)
		}
	}
	if len(tags) == 0 {
		return nil, nil
	}
	return tags, nil
}

// listKMSKeyPolicies follows every ListKeyPolicies page for one key and
// returns the bounded policy revision names. Policy Statement bodies are
// never read here; failures fail the service read, mirroring the in-tree
// adapter.
func listKMSKeyPolicies(ctx context.Context, client kmsDetailAPI, keyID string) ([]string, error) {
	var names []string
	pages := awskms.NewListKeyPoliciesPaginator(client, &awskms.ListKeyPoliciesInput{KeyId: aws.String(keyID)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("kms list key policies: %w", err)
		}
		if page == nil {
			continue
		}
		for _, name := range page.PolicyNames {
			if trimmed := strings.TrimSpace(name); trimmed != "" {
				names = append(names, trimmed)
			}
		}
	}
	return kmsStrings(names), nil
}

// readKMSRotation resolves the rotation answer for one described key,
// skipping the API call for key shapes AWS cannot answer and treating
// UnsupportedOperation/AccessDenied as unknown, mirroring the in-tree
// adapter.
func readKMSRotation(ctx context.Context, client kmsDetailAPI, keyID string, key kmstypes.KeyMetadata) (kmsRotation, error) {
	if !kmsRotationSupported(key) {
		return kmsRotation{}, nil
	}
	output, err := client.GetKeyRotationStatus(ctx, &awskms.GetKeyRotationStatusInput{KeyId: aws.String(keyID)})
	if err != nil {
		if kmsIsUnsupported(err) || kmsIsDenied(err) {
			return kmsRotation{}, nil
		}
		return kmsRotation{}, fmt.Errorf("kms get key rotation status: %w", err)
	}
	if output == nil {
		return kmsRotation{}, nil
	}
	return kmsRotation{known: true, enabled: output.KeyRotationEnabled}, nil
}

// kmsRotationSupported reports whether GetKeyRotationStatus is meaningful for
// this key. AWS answers only for customer-managed symmetric encrypt/decrypt
// keys outside a terminal or creating state, mirroring the in-tree adapter.
func kmsRotationSupported(key kmstypes.KeyMetadata) bool {
	if key.KeyManager != kmstypes.KeyManagerTypeCustomer {
		return false
	}
	if key.KeyUsage != kmstypes.KeyUsageTypeEncryptDecrypt {
		return false
	}
	if key.KeySpec != kmstypes.KeySpecSymmetricDefault {
		return false
	}
	switch key.KeyState {
	case kmstypes.KeyStatePendingDeletion,
		kmstypes.KeyStatePendingReplicaDeletion,
		kmstypes.KeyStateUnavailable,
		kmstypes.KeyStateCreating:
		return false
	}
	return true
}

func kmsIsDenied(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "AccessDenied", "AccessDeniedException":
		return true
	}
	return false
}

func kmsIsUnsupported(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "UnsupportedOperationException", "UnsupportedOperation":
		return true
	}
	return false
}

// kmsTags clones the reported tag set, dropping blank keys, mirroring the
// EKS loader's tag handling.
func kmsTags(tags map[string]string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	result := make(map[string]string, len(tags))
	for key, value := range tags {
		if trimmed := strings.TrimSpace(key); trimmed != "" {
			result[trimmed] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// kmsStrings trims and drops empty names, staying nil for an empty set so
// absent policy names keep the legacy empty shape.
func kmsStrings(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	output := make([]string, 0, len(input))
	for _, value := range input {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			output = append(output, trimmed)
		}
	}
	if len(output) == 0 {
		return nil
	}
	return output
}
