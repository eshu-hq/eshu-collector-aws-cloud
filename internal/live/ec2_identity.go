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
	return record(id, "ec2", region, id, "security-group-rule"), nil
}

func optionalEC2Port(value *int32) any {
	if value == nil {
		return nil
	}
	return *value
}
