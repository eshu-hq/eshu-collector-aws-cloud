// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// subnetRecord retains the metadata the legacy EC2 scanner reads from
// DescribeSubnets. The subnet-to-VPC edge uses the same DescribeSubnets row.
func subnetRecord(subnet ec2types.Subnet, region string) collector.Record {
	id := strings.TrimSpace(aws.ToString(subnet.SubnetId))
	arn := strings.TrimSpace(aws.ToString(subnet.SubnetArn))
	sourceID := id
	if sourceID == "" {
		sourceID = arn
	}
	result := record(sourceID, "ec2", region, ec2Name(subnet.Tags, id), "subnet")
	if result.Resource == nil {
		return result
	}
	resource := result.Resource
	resource.ARN = arn
	resource.Name = id
	resource.State = string(subnet.State)
	resource.Tags = ec2Tags(subnet.Tags)
	resource.Attributes = map[string]any{
		"assign_ipv6_address_on_creation": aws.ToBool(subnet.AssignIpv6AddressOnCreation),
		"availability_zone":               strings.TrimSpace(aws.ToString(subnet.AvailabilityZone)),
		"availability_zone_id":            strings.TrimSpace(aws.ToString(subnet.AvailabilityZoneId)),
		"available_ip_address_count":      aws.ToInt32(subnet.AvailableIpAddressCount),
		"cidr_block":                      strings.TrimSpace(aws.ToString(subnet.CidrBlock)),
		"default_for_az":                  aws.ToBool(subnet.DefaultForAz),
		"ipv6_cidr_block_associations":    subnetIPv6Associations(subnet.Ipv6CidrBlockAssociationSet),
		"ipv6_native":                     aws.ToBool(subnet.Ipv6Native),
		"map_public_ip_on_launch":         aws.ToBool(subnet.MapPublicIpOnLaunch),
		"outpost_arn":                     strings.TrimSpace(aws.ToString(subnet.OutpostArn)),
		"owner_id":                        strings.TrimSpace(aws.ToString(subnet.OwnerId)),
		"vpc_id":                          strings.TrimSpace(aws.ToString(subnet.VpcId)),
	}
	if vpcID := strings.TrimSpace(aws.ToString(subnet.VpcId)); id != "" && vpcID != "" {
		result.Relationship = &collector.LiveRelationship{
			Region: region, ServiceKind: "ec2", RelationshipType: "ec2_subnet_in_vpc",
			SourceResourceID: id, SourceARN: arn, TargetResourceID: vpcID, TargetType: "aws_ec2_vpc",
			SourceRecordID: id + "#vpc#" + vpcID,
		}
	}
	return result
}

func subnetIPv6Associations(input []ec2types.SubnetIpv6CidrBlockAssociation) []map[string]any {
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
			"association_id": strings.TrimSpace(aws.ToString(association.AssociationId)),
			"cidr_block":     strings.TrimSpace(aws.ToString(association.Ipv6CidrBlock)),
			"state":          strings.TrimSpace(state),
		})
	}
	return result
}
