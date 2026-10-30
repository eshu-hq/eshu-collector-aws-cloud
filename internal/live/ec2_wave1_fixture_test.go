// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// wave1EC2Fixture mirrors the shared fixture rows in their in-tree post-mapper
// shape. The satellite bridges below convert each row into AWS SDK input; the
// in-tree oracle unmarshals the same bytes directly into its scanner types.
type wave1EC2Fixture struct {
	ScopeID             string                      `json:"scope_id"`
	GenerationID        string                      `json:"generation_id"`
	CollectorInstanceID string                      `json:"collector_instance_id"`
	VPC                 wave1VPCRow                 `json:"vpc"`
	Subnet              wave1SubnetRow              `json:"subnet"`
	SecurityGroup       wave1SecurityGroupRow       `json:"security_group"`
	SGRules             []wave1SecurityGroupRuleRow `json:"sg_rules"`
	NetworkInterface    wave1NetworkInterfaceRow    `json:"network_interface"`
	Instance            wave1InstanceRow            `json:"instance"`
	Volume              wave1VolumeRow              `json:"volume"`
}

type wave1VPCRow struct {
	ID              string
	OwnerID         string
	State           string
	CIDRBlock       string
	DHCPOptionsID   string
	InstanceTenancy string
	IsDefault       bool
	IPv4CIDRBlocks  []wave1CIDRAssocRow
	IPv6CIDRBlocks  []wave1IPv6CIDRAssocRow
	Tags            map[string]string
}

type wave1CIDRAssocRow struct {
	AssociationID string
	CIDRBlock     string
	State         string
}

type wave1IPv6CIDRAssocRow struct {
	AssociationID      string
	CIDRBlock          string
	State              string
	IPv6Pool           string
	NetworkBorderGroup string
}

type wave1SubnetRow struct {
	ARN                       string
	ID                        string
	VPCID                     string
	OwnerID                   string
	State                     string
	CIDRBlock                 string
	AvailabilityZone          string
	AvailabilityZoneID        string
	AvailableIPAddressCount   int32
	DefaultForAZ              bool
	MapPublicIPOnLaunch       bool
	AssignIPv6AddressOnCreate bool
	IPv6Native                bool
	OutpostARN                string
	IPv6CIDRBlocks            []wave1CIDRAssocRow
	Tags                      map[string]string
}

type wave1SecurityGroupRow struct {
	ID          string
	Name        string
	Description string
	VPCID       string
	OwnerID     string
	Tags        map[string]string
}

type wave1SecurityGroupRuleRow struct {
	ID              string
	GroupID         string
	GroupOwnerID    string
	IsEgress        bool
	Protocol        string
	FromPort        *int32
	ToPort          *int32
	CIDRIPv4        string
	CIDRIPv6        string
	PrefixListID    string
	ReferencedGroup *wave1ReferencedGroupRow
	Description     string
	Tags            map[string]string
}

type wave1ReferencedGroupRow struct {
	GroupID                string
	UserID                 string
	VPCID                  string
	PeeringStatus          string
	VPCPeeringConnectionID string
}

type wave1NetworkInterfaceRow struct {
	ID                 string
	VPCID              string
	SubnetID           string
	OwnerID            string
	Status             string
	InterfaceType      string
	Description        string
	AvailabilityZone   string
	MacAddress         string
	PrivateDNSName     string
	PrivateIPAddress   string
	RequesterID        string
	RequesterManaged   bool
	SourceDestCheck    bool
	SecurityGroups     []wave1GroupRefRow
	PrivateIPAddresses []wave1PrivateIPRow
	IPv6Addresses      []string
	Attachment         *wave1AttachmentRow
	Tags               map[string]string
}

type wave1GroupRefRow struct {
	ID   string
	Name string
}

type wave1PrivateIPRow struct {
	Address        string
	PrivateDNSName string
	Primary        bool
}

type wave1AttachmentRow struct {
	ID                   string
	InstanceID           string
	InstanceOwnerID      string
	AttachedResourceARN  string
	AttachedResourceType string
	Status               string
	AttachTime           time.Time
	DeleteOnTermination  bool
	DeviceIndex          int32
	NetworkCardIndex     int32
}

type wave1InstanceRow struct {
	ID                      string
	ARN                     string
	State                   string
	OwnerID                 string
	InstanceType            string
	SubnetID                string
	VPCID                   string
	ImageID                 string
	IMDSv2Required          *bool
	HTTPEndpoint            string
	HTTPPutResponseHopLimit *int32
	UserDataPresent         *bool
	DetailedMonitoring      bool
	EBSOptimized            bool
	PublicIPAssociated      bool
	PublicIPAddress         string
	InstanceProfileARN      string
	Tenancy                 string
	NitroEnclaveEnabled     bool
	BlockDevices            []wave1BlockDeviceRow
	Tags                    map[string]string
}

type wave1BlockDeviceRow struct {
	DeviceName          string
	VolumeID            string
	DeleteOnTermination bool
	Status              string
	Encrypted           *bool
}

type wave1VolumeRow struct {
	ID                       string
	ARN                      string
	State                    string
	AvailabilityZone         string
	AvailabilityZoneID       string
	CreateTime               time.Time
	Encrypted                *bool
	FastRestored             *bool
	IOPS                     *int32
	KMSKeyID                 string
	MultiAttachEnabled       *bool
	OutpostARN               string
	SizeGiB                  *int32
	SnapshotID               string
	SourceVolumeID           string
	SSEType                  string
	ThroughputMiBps          *int32
	VolumeInitializationRate *int32
	VolumeType               string
	Attachments              []wave1VolumeAttachmentRow
	Tags                     map[string]string
}

type wave1VolumeAttachmentRow struct {
	AssociatedResource    string
	AttachTime            time.Time
	DeleteOnTermination   bool
	Device                string
	EBSCardIndex          *int32
	InstanceID            string
	InstanceOwningService string
	State                 string
	VolumeID              string
}

func loadWave1EC2Fixture(t *testing.T) wave1EC2Fixture {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/wave1-ec2-parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture wave1EC2Fixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
