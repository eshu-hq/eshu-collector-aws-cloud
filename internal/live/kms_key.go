// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// kmsKeyAPI contains only the read calls needed for the key resource slice.
// Alias, grant, policy, tag, and rotation reads belong to later slices.
type kmsKeyAPI interface {
	ListKeys(context.Context, *awskms.ListKeysInput, ...func(*awskms.Options)) (*awskms.ListKeysOutput, error)
	DescribeKey(context.Context, *awskms.DescribeKeyInput, ...func(*awskms.Options)) (*awskms.DescribeKeyOutput, error)
}

func listKMS(ctx context.Context, cfg aws.Config, identity VerifiedIdentity) ([]collector.Record, error) {
	return listKMSWithAPI(ctx, awskms.NewFromConfig(cfg), cfg.Region, identity)
}

// listKMSWithAPI follows every ListKeys page and fails the service read when
// discovery or any required DescribeKey read fails.
func listKMSWithAPI(ctx context.Context, client kmsKeyAPI, region string, identity VerifiedIdentity) ([]collector.Record, error) {
	records := []collector.Record{}
	pages := awskms.NewListKeysPaginator(client, &awskms.ListKeysInput{})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("kms list keys: %w", err)
		}
		for _, key := range page.Keys {
			id := strings.TrimSpace(aws.ToString(key.KeyId))
			if id == "" {
				continue
			}
			described, err := client.DescribeKey(ctx, &awskms.DescribeKeyInput{KeyId: aws.String(id)})
			if err != nil {
				return nil, fmt.Errorf("kms describe key: %w", err)
			}
			if described == nil || described.KeyMetadata == nil {
				return nil, fmt.Errorf("kms DescribeKey returned no metadata")
			}
			row, err := kmsKeyRecord(*described.KeyMetadata, id, region, identity)
			if err != nil {
				return nil, err
			}
			records = append(records, row)
		}
	}
	return records, nil
}

// kmsKeyRecord emits only DescribeKey metadata and the reported key identity.
// It validates ARN scope against the caller identity verified for this claim.
func kmsKeyRecord(key kmstypes.KeyMetadata, listedID, region string, identity VerifiedIdentity) (collector.Record, error) {
	id := strings.TrimSpace(aws.ToString(key.KeyId))
	arn := strings.TrimSpace(aws.ToString(key.Arn))
	parsed, err := awsarn.Parse(arn)
	if err != nil || id == "" || id != listedID || parsed.Service != "kms" || parsed.Region != region || parsed.Partition != identity.Partition || parsed.AccountID != identity.AccountID || parsed.Resource != "key/"+id || !accountPattern.MatchString(parsed.AccountID) {
		return collector.Record{}, fmt.Errorf("kms DescribeKey returned a key outside the claimed identity")
	}
	attrs := map[string]any{
		"key_manager":              strings.TrimSpace(string(key.KeyManager)),
		"key_usage":                strings.TrimSpace(string(key.KeyUsage)),
		"key_spec":                 strings.TrimSpace(string(key.KeySpec)),
		"customer_master_key_spec": "",
		"key_state":                strings.TrimSpace(string(key.KeyState)),
		"origin":                   strings.TrimSpace(string(key.Origin)),
		"description":              strings.TrimSpace(aws.ToString(key.Description)),
		"creation_date":            kmsTime(key.CreationDate),
		"deletion_date":            kmsTime(key.DeletionDate),
		"enabled":                  key.Enabled,
		"multi_region":             aws.ToBool(key.MultiRegion),
		"multi_region_key_type":    kmsMultiRegionType(key.MultiRegionConfiguration),
		"primary_key_arn":          kmsPrimaryKeyARN(key.MultiRegionConfiguration),
		"encryption_algorithms":    kmsAlgorithms(key.EncryptionAlgorithms),
		"signing_algorithms":       kmsSigningAlgorithms(key.SigningAlgorithms),
		"mac_algorithms":           kmsMACAlgorithms(key.MacAlgorithms),
		"key_agreement_algorithms": kmsAgreementAlgorithms(key.KeyAgreementAlgorithms),
	}
	result := record(arn, "kms", region, id, "key")
	result.Resource = &collector.LiveResource{Region: region, ServiceKind: "kms", ResourceType: "aws_kms_key", ResourceID: id, ARN: arn, Name: id, State: string(key.KeyState), Attributes: attrs, CorrelationAnchors: []string{arn, id}, SourceRecordID: arn}
	return result, nil
}

func kmsTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
func kmsMultiRegionType(c *kmstypes.MultiRegionConfiguration) string {
	if c == nil {
		return ""
	}
	return string(c.MultiRegionKeyType)
}
func kmsPrimaryKeyARN(c *kmstypes.MultiRegionConfiguration) string {
	if c == nil || c.PrimaryKey == nil {
		return ""
	}
	return strings.TrimSpace(aws.ToString(c.PrimaryKey.Arn))
}
func kmsAlgorithms(v []kmstypes.EncryptionAlgorithmSpec) []string {
	if len(v) == 0 {
		return nil
	}
	out := make([]string, 0, len(v))
	for _, x := range v {
		out = append(out, string(x))
	}
	return out
}
func kmsSigningAlgorithms(v []kmstypes.SigningAlgorithmSpec) []string {
	if len(v) == 0 {
		return nil
	}
	out := make([]string, 0, len(v))
	for _, x := range v {
		out = append(out, string(x))
	}
	return out
}
func kmsMACAlgorithms(v []kmstypes.MacAlgorithmSpec) []string {
	if len(v) == 0 {
		return nil
	}
	out := make([]string, 0, len(v))
	for _, x := range v {
		out = append(out, string(x))
	}
	return out
}
func kmsAgreementAlgorithms(v []kmstypes.KeyAgreementAlgorithmSpec) []string {
	if len(v) == 0 {
		return nil
	}
	out := make([]string, 0, len(v))
	for _, x := range v {
		out = append(out, string(x))
	}
	return out
}
