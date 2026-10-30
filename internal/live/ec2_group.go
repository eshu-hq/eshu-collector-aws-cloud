// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// securityGroupRecord retains the security group observation returned by
// DescribeSecurityGroups without adding an AWS read.
func securityGroupRecord(group ec2types.SecurityGroup, region string) collector.Record {
	id := strings.TrimSpace(aws.ToString(group.GroupId))
	name := aws.ToString(group.GroupName)
	placeholderName := name
	if placeholderName == "" {
		placeholderName = id
	}
	result := record(id, "ec2", region, placeholderName, "security-group")
	if result.Resource == nil {
		return result
	}
	resource := result.Resource
	resource.Name = name
	resource.CorrelationAnchors = []string{id, strings.TrimSpace(name)}
	resource.Tags = ec2Tags(group.Tags)
	resource.Attributes = map[string]any{
		"description": strings.TrimSpace(aws.ToString(group.Description)),
		"owner_id":    strings.TrimSpace(aws.ToString(group.OwnerId)),
		"vpc_id":      strings.TrimSpace(aws.ToString(group.VpcId)),
	}
	if vpcID := strings.TrimSpace(aws.ToString(group.VpcId)); id != "" && vpcID != "" {
		result.Relationship = &collector.LiveRelationship{
			Region: region, ServiceKind: "ec2", RelationshipType: "ec2_security_group_in_vpc",
			SourceResourceID: id, TargetResourceID: vpcID, TargetType: "aws_ec2_vpc",
			SourceRecordID: id + "#vpc#" + vpcID,
		}
	}
	return result
}
