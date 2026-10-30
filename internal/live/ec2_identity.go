// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// appendEC2Record refuses a source row that cannot produce typed identity.
// The caller treats its error as an EC2 read failure instead of reporting a
// complete scan with a silently missing resource.
func appendEC2Record(records []collector.Record, row collector.Record) ([]collector.Record, error) {
	if row.Resource == nil || strings.TrimSpace(row.Resource.ResourceID) == "" {
		return nil, fmt.Errorf("EC2 resource is missing a source identity")
	}
	return append(records, row), nil
}

// securityGroupRuleRecord retains the legacy scanner's deterministic identity
// when AWS omits SecurityGroupRuleId from a rule returned by DescribeSecurityGroupRules.
func securityGroupRuleRecord(rule ec2types.SecurityGroupRule, region string) (collector.Record, error) {
	id := strings.TrimSpace(aws.ToString(rule.SecurityGroupRuleId))
	if id == "" {
		identity := map[string]any{
			"cidr_ipv4":      strings.TrimSpace(aws.ToString(rule.CidrIpv4)),
			"cidr_ipv6":      strings.TrimSpace(aws.ToString(rule.CidrIpv6)),
			"from_port":      optionalEC2Port(rule.FromPort),
			"group_id":       strings.TrimSpace(aws.ToString(rule.GroupId)),
			"is_egress":      aws.ToBool(rule.IsEgress),
			"prefix_list_id": strings.TrimSpace(aws.ToString(rule.PrefixListId)),
			"protocol":       strings.TrimSpace(aws.ToString(rule.IpProtocol)),
			"to_port":        optionalEC2Port(rule.ToPort),
		}
		encoded, err := json.Marshal(map[string]any{"fact_type": "EC2SecurityGroupRule", "identity": identity})
		if err != nil {
			return collector.Record{}, fmt.Errorf("encode EC2 security-group-rule identity: %w", err)
		}
		digest := sha256.Sum256(encoded)
		id = "security-group-rule:" + hex.EncodeToString(digest[:])
	}
	result := record(id, "ec2", region, id, "security-group-rule")
	resource := result.Resource
	if resource == nil {
		return result, nil
	}
	groupID := strings.TrimSpace(aws.ToString(rule.GroupId))
	direction := "ingress"
	if aws.ToBool(rule.IsEgress) {
		direction = "egress"
	}
	resource.Tags = ec2Tags(rule.Tags)
	resource.CorrelationAnchors = []string{id, groupID}
	resource.Attributes = map[string]any{
		"cidr_ipv4":        strings.TrimSpace(aws.ToString(rule.CidrIpv4)),
		"cidr_ipv6":        strings.TrimSpace(aws.ToString(rule.CidrIpv6)),
		"description":      strings.TrimSpace(aws.ToString(rule.Description)),
		"direction":        direction,
		"from_port":        optionalEC2Port(rule.FromPort),
		"group_id":         groupID,
		"group_owner_id":   strings.TrimSpace(aws.ToString(rule.GroupOwnerId)),
		"ip_protocol":      strings.TrimSpace(aws.ToString(rule.IpProtocol)),
		"is_egress":        aws.ToBool(rule.IsEgress),
		"prefix_list_id":   strings.TrimSpace(aws.ToString(rule.PrefixListId)),
		"referenced_group": referencedSecurityGroupAttributes(rule.ReferencedGroupInfo),
		"to_port":          optionalEC2Port(rule.ToPort),
	}
	if id != "" && groupID != "" {
		result.Relationship = &collector.LiveRelationship{
			Region: region, ServiceKind: "ec2", RelationshipType: "ec2_security_group_has_rule",
			SourceResourceID: groupID, TargetResourceID: id, TargetType: "aws_ec2_security_group_rule",
			Attributes:     map[string]any{"direction": direction},
			SourceRecordID: groupID + "#rule#" + id,
		}
	}
	result.SGPosture = securityGroupRulePosture(rule, region)
	return result, nil
}

// securityGroupRulePosture maps the DescribeSecurityGroupRules row already
// fetched for the resource fact into the normalized aws_security_group_rule
// posture observation. It reuses the in-tree field mapping verbatim: only the
// referenced-group id is flattened, and the raw AWS rule id (blank when AWS
// omits it) feeds the posture identity, never the legacy fallback. The source
// record id stays empty so the seam applies its in-tree-mirrored default. It
// adds no AWS API call.
func securityGroupRulePosture(rule ec2types.SecurityGroupRule, region string) *collector.SecurityGroupRuleObservation {
	var referencedSG string
	if rule.ReferencedGroupInfo != nil {
		referencedSG = strings.TrimSpace(aws.ToString(rule.ReferencedGroupInfo.GroupId))
	}
	return &collector.SecurityGroupRuleObservation{
		Boundary:     collector.Boundary{Region: region, ServiceKind: "ec2"},
		RuleID:       strings.TrimSpace(aws.ToString(rule.SecurityGroupRuleId)),
		GroupID:      strings.TrimSpace(aws.ToString(rule.GroupId)),
		GroupOwnerID: strings.TrimSpace(aws.ToString(rule.GroupOwnerId)),
		IsEgress:     aws.ToBool(rule.IsEgress),
		IPProtocol:   strings.TrimSpace(aws.ToString(rule.IpProtocol)),
		FromPort:     rule.FromPort,
		ToPort:       rule.ToPort,
		CIDRIPv4:     strings.TrimSpace(aws.ToString(rule.CidrIpv4)),
		CIDRIPv6:     strings.TrimSpace(aws.ToString(rule.CidrIpv6)),
		PrefixListID: strings.TrimSpace(aws.ToString(rule.PrefixListId)),
		ReferencedSG: referencedSG,
		Description:  strings.TrimSpace(aws.ToString(rule.Description)),
	}
}

func referencedSecurityGroupAttributes(group *ec2types.ReferencedSecurityGroup) map[string]any {
	if group == nil {
		return nil
	}
	return map[string]any{
		"group_id":                  strings.TrimSpace(aws.ToString(group.GroupId)),
		"peering_status":            strings.TrimSpace(aws.ToString(group.PeeringStatus)),
		"user_id":                   strings.TrimSpace(aws.ToString(group.UserId)),
		"vpc_id":                    strings.TrimSpace(aws.ToString(group.VpcId)),
		"vpc_peering_connection_id": strings.TrimSpace(aws.ToString(group.VpcPeeringConnectionId)),
	}
}

func optionalEC2Port(value *int32) any {
	if value == nil {
		return nil
	}
	return *value
}
