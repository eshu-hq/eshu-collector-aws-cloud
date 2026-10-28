// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// vpcRecord retains the VPC observation that the legacy EC2 scanner builds
// from the same DescribeVpcs response. It makes no additional AWS read.
func vpcRecord(vpc ec2types.Vpc, region string) collector.Record {
	id := strings.TrimSpace(aws.ToString(vpc.VpcId))
	result := record(id, "ec2", region, ec2Name(vpc.Tags, id), "vpc")
	if result.Resource == nil {
		return result
	}
	resource := result.Resource
	resource.State = string(vpc.State)
	resource.Tags = vpcTags(vpc.Tags)
	resource.Attributes = map[string]any{
		"cidr_block":                   strings.TrimSpace(aws.ToString(vpc.CidrBlock)),
		"dhcp_options_id":              strings.TrimSpace(aws.ToString(vpc.DhcpOptionsId)),
		"instance_tenancy":             strings.TrimSpace(string(vpc.InstanceTenancy)),
		"ipv4_cidr_block_associations": vpcIPv4Associations(vpc.CidrBlockAssociationSet),
		"ipv6_cidr_block_associations": vpcIPv6Associations(vpc.Ipv6CidrBlockAssociationSet),
		"is_default":                   aws.ToBool(vpc.IsDefault),
		"owner_id":                     strings.TrimSpace(aws.ToString(vpc.OwnerId)),
	}
	return result
}

func vpcTags(input []ec2types.Tag) map[string]string {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]string, len(input))
	for _, tag := range input {
		key := strings.TrimSpace(aws.ToString(tag.Key))
		if key != "" {
			result[key] = aws.ToString(tag.Value)
		}
	}
	return result
}

func vpcIPv4Associations(input []ec2types.VpcCidrBlockAssociation) []map[string]any {
	if len(input) == 0 {
		return nil
	}
	result := make([]map[string]any, 0, len(input))
	for _, association := range input {
		state := ""
		if association.CidrBlockState != nil {
			state = string(association.CidrBlockState.State)
		}
		result = append(result, map[string]any{
			"association_id": strings.TrimSpace(aws.ToString(association.AssociationId)),
			"cidr_block":     strings.TrimSpace(aws.ToString(association.CidrBlock)),
			"state":          strings.TrimSpace(state),
		})
	}
	return result
}

func vpcIPv6Associations(input []ec2types.VpcIpv6CidrBlockAssociation) []map[string]any {
	if len(input) == 0 {
		return nil
	}
	result := make([]map[string]any, 0, len(input))
	for _, association := range input {
		state := ""
		if association.Ipv6CidrBlockState != nil {
			state = string(association.Ipv6CidrBlockState.State)
		}
		result = append(result, map[string]any{
			"association_id":       strings.TrimSpace(aws.ToString(association.AssociationId)),
			"cidr_block":           strings.TrimSpace(aws.ToString(association.Ipv6CidrBlock)),
			"ipv6_pool":            strings.TrimSpace(aws.ToString(association.Ipv6Pool)),
			"network_border_group": strings.TrimSpace(aws.ToString(association.NetworkBorderGroup)),
			"state":                strings.TrimSpace(state),
		})
	}
	return result
}
