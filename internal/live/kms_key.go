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
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// kmsAliasResourceType and the kmsGrant* relationship types below have no
// constant in the pinned factschema release, so the literals mirror the
// in-tree catalog strings; the parity test locks each value against the
// in-tree oracle key.
const (
	kmsAliasResourceType = "aws_kms_alias"
	kmsGrantResourceType = "aws_kms_grant"
)

const (
	kmsAliasTargetsKeyRelationship = "kms_alias_targets_key"
	kmsGrantOnKeyRelationship      = "kms_grant_on_key"
	kmsGrantForGranteeRelationship = "kms_grant_for_grantee"
	granteePrincipalTypeAWS        = "AWS"
	granteePrincipalTypeService    = "Service"
)

// kmsKeyAPI contains only the read calls needed for the key/alias/grant
// slice: key discovery and metadata plus the alias index and per-key grant
// list. Key-policy, tag, and rotation reads belong to later slices.
type kmsKeyAPI interface {
	ListKeys(context.Context, *awskms.ListKeysInput, ...func(*awskms.Options)) (*awskms.ListKeysOutput, error)
	DescribeKey(context.Context, *awskms.DescribeKeyInput, ...func(*awskms.Options)) (*awskms.DescribeKeyOutput, error)
	ListAliases(context.Context, *awskms.ListAliasesInput, ...func(*awskms.Options)) (*awskms.ListAliasesOutput, error)
	ListGrants(context.Context, *awskms.ListGrantsInput, ...func(*awskms.Options)) (*awskms.ListGrantsOutput, error)
}

func listKMS(ctx context.Context, cfg aws.Config, identity VerifiedIdentity) ([]collector.Record, error) {
	return listKMSWithAPI(ctx, awskms.NewFromConfig(cfg), cfg.Region, identity)
}

// listKMSWithAPI follows every ListKeys page and fails the service read when
// discovery, the alias index, or any required DescribeKey or ListGrants read
// fails. The alias index is read once and joined by target key, mirroring the
// in-tree adapter; grants are listed per key.
func listKMSWithAPI(ctx context.Context, client kmsKeyAPI, region string, identity VerifiedIdentity) ([]collector.Record, error) {
	records := []collector.Record{}
	aliasesByKey, err := listKMSAliasesByKey(ctx, client)
	if err != nil {
		return nil, err
	}
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
			keyARN := strings.TrimSpace(aws.ToString(described.KeyMetadata.Arn))
			for _, alias := range aliasesByKey[id] {
				aliasRecord, err := kmsAliasRecord(alias, id, keyARN, region, identity)
				if err != nil {
					return nil, err
				}
				records = append(records, aliasRecord)
			}
			grants, err := listKMSGrants(ctx, client, id)
			if err != nil {
				return nil, err
			}
			for _, grant := range grants {
				grantRecord, err := kmsGrantRecord(grant, id, keyARN, region)
				if err != nil {
					return nil, err
				}
				records = append(records, grantRecord)
			}
		}
	}
	return records, nil
}

// listKMSAliasesByKey pages the account-wide alias list once and indexes
// entries by target key. Entries without a target never join a key and are
// dropped here, mirroring the in-tree adapter.
func listKMSAliasesByKey(ctx context.Context, client kmsKeyAPI) (map[string][]kmstypes.AliasListEntry, error) {
	aliasesByKey := map[string][]kmstypes.AliasListEntry{}
	pages := awskms.NewListAliasesPaginator(client, &awskms.ListAliasesInput{})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("kms list aliases: %w", err)
		}
		for _, alias := range page.Aliases {
			targetID := strings.TrimSpace(aws.ToString(alias.TargetKeyId))
			if targetID == "" {
				continue
			}
			aliasesByKey[targetID] = append(aliasesByKey[targetID], alias)
		}
	}
	return aliasesByKey, nil
}

// listKMSGrants follows every ListGrants page for one key and fails the
// service read when the grant list cannot be completed.
func listKMSGrants(ctx context.Context, client kmsKeyAPI, keyID string) ([]kmstypes.GrantListEntry, error) {
	var grants []kmstypes.GrantListEntry
	pages := awskms.NewListGrantsPaginator(client, &awskms.ListGrantsInput{KeyId: aws.String(keyID)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("kms list grants: %w", err)
		}
		grants = append(grants, page.Grants...)
	}
	return grants, nil
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

// kmsAliasRecord maps one ListAliases row into the typed alias resource plus
// its alias-to-key edge, mirroring the in-tree KMS scanner's alias
// observation field for field. A reported alias ARN must scope to the claimed
// identity; a missing alias ARN still identifies by alias name, and the edge
// carries the same fallback. It adds no AWS API call.
func kmsAliasRecord(alias kmstypes.AliasListEntry, keyID, keyARN, region string, identity VerifiedIdentity) (collector.Record, error) {
	name := strings.TrimSpace(aws.ToString(alias.AliasName))
	arn := strings.TrimSpace(aws.ToString(alias.AliasArn))
	targetID := strings.TrimSpace(aws.ToString(alias.TargetKeyId))
	if name == "" || targetID == "" || targetID != keyID {
		return collector.Record{}, fmt.Errorf("kms ListAliases returned an alias outside the joined key")
	}
	aliasID := arn
	if aliasID == "" {
		aliasID = name
	}
	if arn != "" {
		parsed, err := awsarn.Parse(arn)
		if err != nil || parsed.Service != "kms" || parsed.Region != region || parsed.Partition != identity.Partition || parsed.AccountID != identity.AccountID || !accountPattern.MatchString(parsed.AccountID) || !strings.HasPrefix(parsed.Resource, "alias/") {
			return collector.Record{}, fmt.Errorf("kms ListAliases returned an alias outside the claimed identity")
		}
	}
	result := record(arn, "kms", region, name, "alias")
	result.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "kms", ResourceType: kmsAliasResourceType,
		ResourceID: aliasID, ARN: arn, Name: name, SourceRecordID: aliasID,
		CorrelationAnchors: []string{arn, name},
		Attributes: map[string]any{
			"alias_name":    name,
			"target_key_id": keyID,
			"last_updated":  kmsTime(alias.LastUpdatedDate),
		},
	}
	result.Relationship = &collector.LiveRelationship{
		Region: region, ServiceKind: "kms", RelationshipType: kmsAliasTargetsKeyRelationship,
		SourceResourceID: aliasID, SourceARN: arn,
		TargetResourceID: keyID, TargetARN: keyARN, TargetType: awsv1.ResourceTypeKMSKey,
		SourceRecordID: aliasID + "->" + keyID,
		Attributes:     map[string]any{"alias_name": name},
	}
	return result, nil
}

// kmsGrantRecord maps one ListGrants row into the typed grant resource, its
// grant-to-key edge, and — when the grant names a grantee — its
// grant-to-grantee edge, mirroring the in-tree KMS scanner's grant
// observations field for field. Grant encryption contexts and constraint
// expressions never enter a fact. It adds no AWS API call.
func kmsGrantRecord(grant kmstypes.GrantListEntry, keyID, keyARN, region string) (collector.Record, error) {
	grantID := strings.TrimSpace(aws.ToString(grant.GrantId))
	if grantID == "" {
		return collector.Record{}, fmt.Errorf("kms ListGrants returned a grant without identity")
	}
	resourceID := keyID + "/grant/" + grantID
	name := strings.TrimSpace(aws.ToString(grant.Name))
	if name == "" {
		name = grantID
	}
	grantee, granteeType := kmsGrantPrincipal(aws.ToString(grant.GranteePrincipal), aws.ToString(grant.GranteeServicePrincipal))
	retiring, _ := kmsGrantPrincipal(aws.ToString(grant.RetiringPrincipal), aws.ToString(grant.RetiringServicePrincipal))
	result := record("", "kms", region, grantID, "grant")
	result.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "kms", ResourceType: kmsGrantResourceType,
		ResourceID: resourceID, Name: name, SourceRecordID: resourceID,
		CorrelationAnchors: []string{grantID, resourceID},
		Attributes: map[string]any{
			"grant_id":           grantID,
			"grant_name":         strings.TrimSpace(aws.ToString(grant.Name)),
			"key_id":             keyID,
			"creation_date":      kmsTime(grant.CreationDate),
			"grantee_principal":  grantee,
			"retiring_principal": retiring,
			"issuing_account":    strings.TrimSpace(aws.ToString(grant.IssuingAccount)),
			"operations":         kmsGrantOperations(grant.Operations),
		},
	}
	result.Relationship = &collector.LiveRelationship{
		Region: region, ServiceKind: "kms", RelationshipType: kmsGrantOnKeyRelationship,
		SourceResourceID: resourceID,
		TargetResourceID: keyID, TargetARN: keyARN, TargetType: awsv1.ResourceTypeKMSKey,
		SourceRecordID: resourceID + "->" + keyID,
		Attributes:     map[string]any{"grant_id": grantID},
	}
	if grantee == "" {
		return result, nil
	}
	principalID := granteeType + ":" + grantee
	granteeEdge := collector.LiveRelationship{
		Region: region, ServiceKind: "kms", RelationshipType: kmsGrantForGranteeRelationship,
		SourceResourceID: resourceID,
		TargetResourceID: principalID, TargetType: awsv1.ResourceTypeIAMPrincipal,
		SourceRecordID: resourceID + "->" + principalID,
		Attributes: map[string]any{
			"grant_id":           grantID,
			"principal_type":     granteeType,
			"retiring_principal": retiring,
		},
	}
	// A service principal is not an ARN: only an IAM grantee populates the
	// target ARN, mirroring the in-tree scanner.
	if granteeType == granteePrincipalTypeAWS {
		granteeEdge.TargetARN = grantee
	}
	result.Relationships = append(result.Relationships, granteeEdge)
	return result, nil
}

// kmsGrantPrincipal mirrors the in-tree adapter's principal classification: an
// IAM ARN classifies as AWS, an AWS service principal as Service, and the
// type is empty when neither field is set.
func kmsGrantPrincipal(arnPrincipal, servicePrincipal string) (string, string) {
	if trimmed := strings.TrimSpace(arnPrincipal); trimmed != "" {
		return trimmed, granteePrincipalTypeAWS
	}
	if trimmed := strings.TrimSpace(servicePrincipal); trimmed != "" {
		return trimmed, granteePrincipalTypeService
	}
	return "", ""
}

// kmsGrantOperations mirrors the in-tree adapter's operation projection: the
// bounded operation names in reported order, nil when the grant lists none.
func kmsGrantOperations(operations []kmstypes.GrantOperation) []string {
	if len(operations) == 0 {
		return nil
	}
	out := make([]string, 0, len(operations))
	for _, operation := range operations {
		if trimmed := strings.TrimSpace(string(operation)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
