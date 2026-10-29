// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// networkInterfaceRecord retains the legacy EC2 resource observation from
// DescribeNetworkInterfaces. Attachment identity uses the verified caller's
// account and partition when AWS does not report an instance owner.
func networkInterfaceRecord(iface ec2types.NetworkInterface, region string, identity VerifiedIdentity) collector.Record {
	id := strings.TrimSpace(aws.ToString(iface.NetworkInterfaceId))
	result := record(id, "ec2", region, id, "network-interface")
	if result.Resource == nil {
		return result
	}
	resource := result.Resource
	resource.State = string(iface.Status)
	resource.Tags = ec2Tags(iface.TagSet)
	resource.CorrelationAnchors = []string{id}
	attachment := networkInterfaceAttachment(iface.Attachment, region, identity)
	resource.Attributes = map[string]any{
		"attachment":                 attachment,
		"availability_zone":          strings.TrimSpace(aws.ToString(iface.AvailabilityZone)),
		"description":                strings.TrimSpace(aws.ToString(iface.Description)),
		"interface_type":             strings.TrimSpace(string(iface.InterfaceType)),
		"ipv6_addresses":             networkInterfaceIPv6Addresses(iface.Ipv6Addresses),
		"mac_address":                strings.TrimSpace(aws.ToString(iface.MacAddress)),
		"owner_id":                   strings.TrimSpace(aws.ToString(iface.OwnerId)),
		"primary_private_ip_address": strings.TrimSpace(aws.ToString(iface.PrivateIpAddress)),
		"private_dns_name":           strings.TrimSpace(aws.ToString(iface.PrivateDnsName)),
		"private_ip_addresses":       networkInterfacePrivateIPs(iface.PrivateIpAddresses),
		"requester_id":               strings.TrimSpace(aws.ToString(iface.RequesterId)),
		"requester_managed":          aws.ToBool(iface.RequesterManaged),
		"security_groups":            networkInterfaceSecurityGroups(iface.Groups),
		"source_dest_check":          aws.ToBool(iface.SourceDestCheck),
		"subnet_id":                  strings.TrimSpace(aws.ToString(iface.SubnetId)),
		"vpc_id":                     strings.TrimSpace(aws.ToString(iface.VpcId)),
	}
	result.Relationships = networkInterfaceRelationships(iface, region, attachment)
	return result
}

func networkInterfaceRelationships(iface ec2types.NetworkInterface, region string, attachment map[string]any) []collector.LiveRelationship {
	id := strings.TrimSpace(aws.ToString(iface.NetworkInterfaceId))
	if id == "" {
		return nil
	}
	base := collector.LiveRelationship{Region: region, ServiceKind: "ec2", SourceResourceID: id}
	var edges []collector.LiveRelationship
	if subnetID := strings.TrimSpace(aws.ToString(iface.SubnetId)); subnetID != "" {
		edge := base
		edge.RelationshipType, edge.TargetResourceID, edge.TargetType = "ec2_network_interface_in_subnet", subnetID, "aws_ec2_subnet"
		edge.SourceRecordID = id + "#subnet#" + subnetID
		edges = append(edges, edge)
	}
	if vpcID := strings.TrimSpace(aws.ToString(iface.VpcId)); vpcID != "" {
		edge := base
		edge.RelationshipType, edge.TargetResourceID, edge.TargetType = "ec2_network_interface_in_vpc", vpcID, "aws_ec2_vpc"
		edge.SourceRecordID = id + "#vpc#" + vpcID
		edges = append(edges, edge)
	}
	for _, group := range iface.Groups {
		groupID := strings.TrimSpace(aws.ToString(group.GroupId))
		if groupID == "" {
			continue
		}
		edge := base
		edge.RelationshipType, edge.TargetResourceID, edge.TargetType = "ec2_network_interface_uses_security_group", groupID, "aws_ec2_security_group"
		edge.SourceRecordID = id + "#security-group#" + groupID
		edge.Attributes = map[string]any{"group_name": strings.TrimSpace(aws.ToString(group.GroupName))}
		edges = append(edges, edge)
	}
	if attachment != nil {
		targetID := strings.TrimSpace(aws.ToString(iface.Attachment.InstanceId))
		targetARN, ok := attachment["attached_resource_arn"].(string)
		if !ok {
			targetARN = ""
		}
		if targetID == "" {
			targetID = targetARN
		}
		if targetID != "" {
			edge := base
			edge.RelationshipType, edge.TargetResourceID = "ec2_network_interface_attached_to_resource", targetID
			edge.TargetARN = targetARN
			edge.TargetType, ok = attachment["attached_resource_type"].(string)
			if !ok {
				edge.TargetType = ""
			}
			edge.SourceRecordID = id + "#attachment#" + targetID
			edge.Attributes = attachment
			edges = append(edges, edge)
		}
	}
	return edges
}

func networkInterfaceAttachment(attachment *ec2types.NetworkInterfaceAttachment, region string, identity VerifiedIdentity) map[string]any {
	if attachment == nil {
		return nil
	}
	instanceID := strings.TrimSpace(aws.ToString(attachment.InstanceId))
	ownerID := strings.TrimSpace(aws.ToString(attachment.InstanceOwnerId))
	if ownerID == "" {
		ownerID = identity.AccountID
	}
	instanceARN := ""
	instanceType := ""
	if instanceID != "" {
		instanceType = "aws_ec2_instance"
		if region != "" && ownerID != "" {
			instanceARN = "arn:" + identity.Partition + ":ec2:" + region + ":" + ownerID + ":instance/" + instanceID
		}
	}
	var attachTime any
	if observed := aws.ToTime(attachment.AttachTime); !observed.IsZero() {
		attachTime = observed.UTC()
	}
	return map[string]any{
		"attached_resource_arn":  instanceARN,
		"attached_resource_type": instanceType,
		"attach_time":            attachTime,
		"attachment_id":          strings.TrimSpace(aws.ToString(attachment.AttachmentId)),
		"delete_on_termination":  aws.ToBool(attachment.DeleteOnTermination),
		"device_index":           aws.ToInt32(attachment.DeviceIndex),
		"instance_id":            instanceID,
		"instance_owner_id":      ownerID,
		"network_card_index":     aws.ToInt32(attachment.NetworkCardIndex),
		"status":                 strings.TrimSpace(string(attachment.Status)),
	}
}

func networkInterfaceSecurityGroups(groups []ec2types.GroupIdentifier) []map[string]string {
	if len(groups) == 0 {
		return nil
	}
	result := make([]map[string]string, 0, len(groups))
	for _, group := range groups {
		result = append(result, map[string]string{
			"group_id":   strings.TrimSpace(aws.ToString(group.GroupId)),
			"group_name": strings.TrimSpace(aws.ToString(group.GroupName)),
		})
	}
	return result
}

func networkInterfacePrivateIPs(addresses []ec2types.NetworkInterfacePrivateIpAddress) []map[string]any {
	if len(addresses) == 0 {
		return nil
	}
	result := make([]map[string]any, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, map[string]any{
			"private_dns_name": strings.TrimSpace(aws.ToString(address.PrivateDnsName)),
			"private_ip":       strings.TrimSpace(aws.ToString(address.PrivateIpAddress)),
			"primary":          aws.ToBool(address.Primary),
		})
	}
	return result
}

func networkInterfaceIPv6Addresses(addresses []ec2types.NetworkInterfaceIpv6Address) []string {
	if len(addresses) == 0 {
		return nil
	}
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if value := strings.TrimSpace(aws.ToString(address.Ipv6Address)); value != "" {
			result = append(result, value)
		}
	}
	return result
}
