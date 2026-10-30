// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func wave1SDKTags(tags map[string]string) []ec2types.Tag {
	if len(tags) == 0 {
		return nil
	}
	out := make([]ec2types.Tag, 0, len(tags))
	for key, value := range tags {
		key, value := key, value
		out = append(out, ec2types.Tag{Key: aws.String(key), Value: aws.String(value)})
	}
	return out
}

func wave1SDKVPC(t *testing.T, fixture wave1EC2Fixture) ec2types.Vpc {
	t.Helper()
	row := fixture.VPC
	vpc := ec2types.Vpc{
		VpcId:           aws.String(row.ID),
		OwnerId:         aws.String(row.OwnerID),
		State:           ec2types.VpcState(row.State),
		CidrBlock:       aws.String(row.CIDRBlock),
		DhcpOptionsId:   aws.String(row.DHCPOptionsID),
		InstanceTenancy: ec2types.Tenancy(row.InstanceTenancy),
		IsDefault:       aws.Bool(row.IsDefault),
		Tags:            wave1SDKTags(row.Tags),
	}
	for _, assoc := range row.IPv4CIDRBlocks {
		assoc := assoc
		vpc.CidrBlockAssociationSet = append(vpc.CidrBlockAssociationSet, ec2types.VpcCidrBlockAssociation{
			AssociationId: aws.String(assoc.AssociationID),
			CidrBlock:     aws.String(assoc.CIDRBlock),
			CidrBlockState: &ec2types.VpcCidrBlockState{
				State: ec2types.VpcCidrBlockStateCode(assoc.State),
			},
		})
	}
	for _, assoc := range row.IPv6CIDRBlocks {
		assoc := assoc
		vpc.Ipv6CidrBlockAssociationSet = append(vpc.Ipv6CidrBlockAssociationSet, ec2types.VpcIpv6CidrBlockAssociation{
			AssociationId: aws.String(assoc.AssociationID),
			Ipv6CidrBlock: aws.String(assoc.CIDRBlock),
			Ipv6CidrBlockState: &ec2types.VpcCidrBlockState{
				State: ec2types.VpcCidrBlockStateCode(assoc.State),
			},
			Ipv6Pool:           aws.String(assoc.IPv6Pool),
			NetworkBorderGroup: aws.String(assoc.NetworkBorderGroup),
		})
	}
	return vpc
}

func wave1SDKSubnet(t *testing.T, fixture wave1EC2Fixture) ec2types.Subnet {
	t.Helper()
	row := fixture.Subnet
	subnet := ec2types.Subnet{
		SubnetId:                    aws.String(row.ID),
		SubnetArn:                   aws.String(row.ARN),
		VpcId:                       aws.String(row.VPCID),
		OwnerId:                     aws.String(row.OwnerID),
		State:                       ec2types.SubnetState(row.State),
		CidrBlock:                   aws.String(row.CIDRBlock),
		AvailabilityZone:            aws.String(row.AvailabilityZone),
		AvailabilityZoneId:          aws.String(row.AvailabilityZoneID),
		AvailableIpAddressCount:     aws.Int32(row.AvailableIPAddressCount),
		DefaultForAz:                aws.Bool(row.DefaultForAZ),
		MapPublicIpOnLaunch:         aws.Bool(row.MapPublicIPOnLaunch),
		AssignIpv6AddressOnCreation: aws.Bool(row.AssignIPv6AddressOnCreate),
		Ipv6Native:                  aws.Bool(row.IPv6Native),
		OutpostArn:                  aws.String(row.OutpostARN),
		Tags:                        wave1SDKTags(row.Tags),
	}
	for _, assoc := range row.IPv6CIDRBlocks {
		assoc := assoc
		subnet.Ipv6CidrBlockAssociationSet = append(subnet.Ipv6CidrBlockAssociationSet, ec2types.SubnetIpv6CidrBlockAssociation{
			AssociationId: aws.String(assoc.AssociationID),
			Ipv6CidrBlock: aws.String(assoc.CIDRBlock),
			Ipv6CidrBlockState: &ec2types.SubnetCidrBlockState{
				State: ec2types.SubnetCidrBlockStateCode(assoc.State),
			},
		})
	}
	return subnet
}

func wave1SDKSecurityGroup(t *testing.T, fixture wave1EC2Fixture) ec2types.SecurityGroup {
	t.Helper()
	row := fixture.SecurityGroup
	return ec2types.SecurityGroup{
		GroupId:     aws.String(row.ID),
		GroupName:   aws.String(row.Name),
		Description: aws.String(row.Description),
		VpcId:       aws.String(row.VPCID),
		OwnerId:     aws.String(row.OwnerID),
		Tags:        wave1SDKTags(row.Tags),
	}
}

func wave1SDKRules(t *testing.T, fixture wave1EC2Fixture) []ec2types.SecurityGroupRule {
	t.Helper()
	var out []ec2types.SecurityGroupRule
	for _, row := range fixture.SGRules {
		row := row
		rule := ec2types.SecurityGroupRule{
			SecurityGroupRuleId: aws.String(row.ID),
			GroupId:             aws.String(row.GroupID),
			GroupOwnerId:        aws.String(row.GroupOwnerID),
			IsEgress:            aws.Bool(row.IsEgress),
			IpProtocol:          aws.String(row.Protocol),
			FromPort:            row.FromPort,
			ToPort:              row.ToPort,
			CidrIpv4:            aws.String(row.CIDRIPv4),
			CidrIpv6:            aws.String(row.CIDRIPv6),
			PrefixListId:        aws.String(row.PrefixListID),
			Description:         aws.String(row.Description),
			Tags:                wave1SDKTags(row.Tags),
		}
		if row.ReferencedGroup != nil {
			group := row.ReferencedGroup
			rule.ReferencedGroupInfo = &ec2types.ReferencedSecurityGroup{
				GroupId:                aws.String(group.GroupID),
				UserId:                 aws.String(group.UserID),
				VpcId:                  aws.String(group.VPCID),
				PeeringStatus:          aws.String(group.PeeringStatus),
				VpcPeeringConnectionId: aws.String(group.VPCPeeringConnectionID),
			}
		}
		if rule.SecurityGroupRuleId != nil && *rule.SecurityGroupRuleId == "" {
			rule.SecurityGroupRuleId = nil
		}
		out = append(out, rule)
	}
	return out
}

func wave1SDKNetworkInterface(t *testing.T, fixture wave1EC2Fixture) ec2types.NetworkInterface {
	t.Helper()
	row := fixture.NetworkInterface
	iface := ec2types.NetworkInterface{
		NetworkInterfaceId: aws.String(row.ID),
		VpcId:              aws.String(row.VPCID),
		SubnetId:           aws.String(row.SubnetID),
		OwnerId:            aws.String(row.OwnerID),
		Status:             ec2types.NetworkInterfaceStatus(row.Status),
		InterfaceType:      ec2types.NetworkInterfaceType(row.InterfaceType),
		Description:        aws.String(row.Description),
		AvailabilityZone:   aws.String(row.AvailabilityZone),
		MacAddress:         aws.String(row.MacAddress),
		PrivateDnsName:     aws.String(row.PrivateDNSName),
		PrivateIpAddress:   aws.String(row.PrivateIPAddress),
		RequesterId:        aws.String(row.RequesterID),
		RequesterManaged:   aws.Bool(row.RequesterManaged),
		SourceDestCheck:    aws.Bool(row.SourceDestCheck),
		TagSet:             wave1SDKTags(row.Tags),
	}
	for _, group := range row.SecurityGroups {
		group := group
		iface.Groups = append(iface.Groups, ec2types.GroupIdentifier{
			GroupId:   aws.String(group.ID),
			GroupName: aws.String(group.Name),
		})
	}
	for _, address := range row.PrivateIPAddresses {
		address := address
		iface.PrivateIpAddresses = append(iface.PrivateIpAddresses, ec2types.NetworkInterfacePrivateIpAddress{
			PrivateIpAddress: aws.String(address.Address),
			PrivateDnsName:   aws.String(address.PrivateDNSName),
			Primary:          aws.Bool(address.Primary),
		})
	}
	for _, address := range row.IPv6Addresses {
		address := address
		iface.Ipv6Addresses = append(iface.Ipv6Addresses, ec2types.NetworkInterfaceIpv6Address{
			Ipv6Address: aws.String(address),
		})
	}
	if row.Attachment != nil {
		attachment := row.Attachment
		// The bridge carries only the API-reported attachment identity: the
		// satellite builder synthesizes the attached-resource ARN from the
		// verified caller identity, exactly as the in-tree mapper does.
		iface.Attachment = &ec2types.NetworkInterfaceAttachment{
			AttachmentId:        aws.String(attachment.ID),
			InstanceId:          aws.String(attachment.InstanceID),
			InstanceOwnerId:     aws.String(attachment.InstanceOwnerID),
			Status:              ec2types.AttachmentStatus(attachment.Status),
			AttachTime:          aws.Time(attachment.AttachTime),
			DeleteOnTermination: aws.Bool(attachment.DeleteOnTermination),
			DeviceIndex:         aws.Int32(attachment.DeviceIndex),
			NetworkCardIndex:    aws.Int32(attachment.NetworkCardIndex),
		}
		if *iface.Attachment.InstanceOwnerId == "" {
			iface.Attachment.InstanceOwnerId = nil
		}
	}
	return iface
}

func wave1SDKInstance(t *testing.T, fixture wave1EC2Fixture) ec2types.Instance {
	t.Helper()
	row := fixture.Instance
	instance := ec2types.Instance{
		InstanceId:   aws.String(row.ID),
		ImageId:      aws.String(row.ImageID),
		State:        &ec2types.InstanceState{Name: ec2types.InstanceStateName(row.State)},
		InstanceType: ec2types.InstanceType(row.InstanceType),
		SubnetId:     aws.String(row.SubnetID),
		VpcId:        aws.String(row.VPCID),
		MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
			HttpTokens:              ec2types.HttpTokensState(row.IMDSv2RequiredToken()),
			HttpEndpoint:            ec2types.InstanceMetadataEndpointState(row.HTTPEndpoint),
			HttpPutResponseHopLimit: row.HTTPPutResponseHopLimit,
		},
		Monitoring:   &ec2types.Monitoring{State: ec2types.MonitoringState(row.MonitoringState())},
		EbsOptimized: aws.Bool(row.EBSOptimized),
		IamInstanceProfile: &ec2types.IamInstanceProfile{
			Arn: aws.String(row.InstanceProfileARN),
		},
		Placement:      &ec2types.Placement{Tenancy: ec2types.Tenancy(row.Tenancy)},
		EnclaveOptions: &ec2types.EnclaveOptions{Enabled: aws.Bool(row.NitroEnclaveEnabled)},
		Tags:           wave1SDKTags(row.Tags),
	}
	if row.IMDSv2Required == nil {
		instance.MetadataOptions = nil
	}
	if row.PublicIPAssociated {
		instance.PublicIpAddress = aws.String(row.PublicIPAddress)
	}
	for _, device := range row.BlockDevices {
		device := device
		mapping := ec2types.InstanceBlockDeviceMapping{
			DeviceName: aws.String(device.DeviceName),
			Ebs: &ec2types.EbsInstanceBlockDevice{
				VolumeId:            aws.String(device.VolumeID),
				DeleteOnTermination: aws.Bool(device.DeleteOnTermination),
				Status:              ec2types.AttachmentStatus(device.Status),
			},
		}
		instance.BlockDeviceMappings = append(instance.BlockDeviceMappings, mapping)
	}
	return instance
}

// IMDSv2RequiredToken renders the fixture boolean as the API token state the
// mapper reads. The presence-only contract never consults user-data content.
func (row wave1InstanceRow) IMDSv2RequiredToken() string {
	if row.IMDSv2Required != nil && *row.IMDSv2Required {
		return "required"
	}
	return "optional"
}

// MonitoringState renders the fixture monitoring flag as the API state.
func (row wave1InstanceRow) MonitoringState() string {
	if row.DetailedMonitoring {
		return "enabled"
	}
	return "disabled"
}

func wave1SDKVolume(t *testing.T, fixture wave1EC2Fixture) ec2types.Volume {
	t.Helper()
	row := fixture.Volume
	volume := ec2types.Volume{
		VolumeId:                 aws.String(row.ID),
		State:                    ec2types.VolumeState(row.State),
		AvailabilityZone:         aws.String(row.AvailabilityZone),
		AvailabilityZoneId:       aws.String(row.AvailabilityZoneID),
		CreateTime:               aws.Time(row.CreateTime),
		Encrypted:                row.Encrypted,
		FastRestored:             row.FastRestored,
		Iops:                     row.IOPS,
		KmsKeyId:                 aws.String(row.KMSKeyID),
		MultiAttachEnabled:       row.MultiAttachEnabled,
		OutpostArn:               aws.String(row.OutpostARN),
		Size:                     row.SizeGiB,
		SnapshotId:               aws.String(row.SnapshotID),
		SourceVolumeId:           aws.String(row.SourceVolumeID),
		SseType:                  ec2types.SSEType(row.SSEType),
		Throughput:               row.ThroughputMiBps,
		VolumeInitializationRate: row.VolumeInitializationRate,
		VolumeType:               ec2types.VolumeType(row.VolumeType),
		Tags:                     wave1SDKTags(row.Tags),
	}
	for _, attachment := range row.Attachments {
		attachment := attachment
		volume.Attachments = append(volume.Attachments, ec2types.VolumeAttachment{
			AssociatedResource:    aws.String(attachment.AssociatedResource),
			AttachTime:            aws.Time(attachment.AttachTime),
			DeleteOnTermination:   aws.Bool(attachment.DeleteOnTermination),
			Device:                aws.String(attachment.Device),
			EbsCardIndex:          attachment.EBSCardIndex,
			InstanceId:            aws.String(attachment.InstanceID),
			InstanceOwningService: aws.String(attachment.InstanceOwningService),
			State:                 ec2types.VolumeAttachmentState(attachment.State),
			VolumeId:              aws.String(attachment.VolumeID),
		})
	}
	return volume
}
