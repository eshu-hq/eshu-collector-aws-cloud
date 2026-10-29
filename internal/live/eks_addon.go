// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// eksAddonRecord carries the reported managed add-on fields from DescribeAddon.
// Configuration values are excluded because they may contain secrets.
func eksAddonRecord(addon ekstypes.Addon, region string) (collector.Record, error) {
	arn := strings.TrimSpace(aws.ToString(addon.AddonArn))
	name := strings.TrimSpace(aws.ToString(addon.AddonName))
	clusterName := strings.TrimSpace(aws.ToString(addon.ClusterName))
	id := arn
	if id == "" && clusterName != "" && name != "" {
		id = clusterName + "/" + name
	}
	if id == "" {
		return collector.Record{}, fmt.Errorf("EKS addon has no source identity")
	}
	roleARN := strings.TrimSpace(aws.ToString(addon.ServiceAccountRoleArn))
	attrs := map[string]any{
		"addon_version":            strings.TrimSpace(aws.ToString(addon.AddonVersion)),
		"cluster_name":             clusterName,
		"created_at":               nil,
		"modified_at":              nil,
		"service_account_role_arn": roleARN,
	}
	if addon.CreatedAt != nil && !addon.CreatedAt.IsZero() {
		attrs["created_at"] = addon.CreatedAt.UTC()
	}
	if addon.ModifiedAt != nil && !addon.ModifiedAt.IsZero() {
		attrs["modified_at"] = addon.ModifiedAt.UTC()
	}
	result := record(arn, "eks", region, name, "addon")
	result.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "eks", ResourceType: "aws_eks_addon",
		ResourceID: id, ARN: arn, Name: name, State: strings.TrimSpace(string(addon.Status)),
		Tags: eksTags(addon.Tags), Attributes: attrs,
		CorrelationAnchors: []string{id, name, roleARN}, SourceRecordID: id,
	}
	return result, nil
}
