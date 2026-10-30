// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// wave1EKSFixture mirrors the shared fixture rows in their in-tree
// post-mapper shape. The stub below serves the same rows as EKS/IAM API
// responses; the in-tree oracle unmarshals the same bytes directly into its
// scanner types.
type wave1EKSFixture struct {
	ScopeID             string                 `json:"scope_id"`
	GenerationID        string                 `json:"generation_id"`
	CollectorInstanceID string                 `json:"collector_instance_id"`
	Clusters            []wave1EKSClusterRow   `json:"clusters"`
	Nodegroups          []wave1EKSNodegroupRow `json:"nodegroups"`
	Addons              []wave1EKSAddonRow     `json:"addons"`
}

type wave1EKSClusterRow struct {
	ARN             string
	Name            string
	Version         string
	PlatformVersion string
	Status          string
	Endpoint        string
	RoleARN         string
	CreatedAt       time.Time
	OIDCProvider    wave1EKSOIDCProviderRow
	VPCConfig       wave1EKSVPCConfigRow
	Tags            map[string]string
}

type wave1EKSOIDCProviderRow struct {
	ARN         string
	IssuerURL   string
	Thumbprints []string
	ClientIDs   []string
}

type wave1EKSVPCConfigRow struct {
	VPCID                  string
	SubnetIDs              []string
	SecurityGroupIDs       []string
	ClusterSecurityGroupID string
	EndpointPublicAccess   bool
	EndpointPrivateAccess  bool
	PublicAccessCIDRs      []string
}

type wave1EKSNodegroupRow struct {
	ARN            string
	Name           string
	ClusterName    string
	Version        string
	ReleaseVersion string
	Status         string
	NodeRoleARN    string
	CapacityType   string
	AMIType        string
	InstanceTypes  []string
	Subnets        []string
	ScalingConfig  wave1EKSScalingConfigRow
	Tags           map[string]string
}

type wave1EKSScalingConfigRow struct {
	DesiredSize int32
	MinSize     int32
	MaxSize     int32
}

type wave1EKSAddonRow struct {
	ARN                   string
	Name                  string
	ClusterName           string
	Version               string
	Status                string
	ServiceAccountRoleARN string
	CreatedAt             time.Time
	ModifiedAt            time.Time
	Tags                  map[string]string
}

func loadWave1EKSFixture(t *testing.T) wave1EKSFixture {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/wave1-eks-parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture wave1EKSFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
