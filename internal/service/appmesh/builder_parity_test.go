// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package appmesh

import (
	"reflect"
	"testing"

	awscloud "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

func testBoundary() awscloud.Boundary {
	return awscloud.Boundary{
		AccountID:    "123456789012",
		Region:       "us-east-1",
		ServiceKind:  catalog.ServiceAppMesh,
		ScopeID:      "scope-1",
		GenerationID: "gen-1",
	}
}

// TestPortParity_VirtualServiceInMesh freezes the mesh-membership edge,
// including the empty-ARN nil contract.
func TestPortParity_VirtualServiceInMesh(t *testing.T) {
	t.Parallel()
	mesh := Mesh{ARN: "arn:aws:appmesh:us-east-1:123456789012:mesh/m", Name: "m"}
	svc := VirtualService{ARN: "arn:aws:appmesh:us-east-1:123456789012:mesh/m/virtualService/s.apps.local", Name: "s.apps.local"}
	got := virtualServiceRelationships(testBoundary(), mesh, svc)
	want := []awscloud.RelationshipObservation{{
		Boundary:         testBoundary(),
		RelationshipType: catalog.RelationshipAppMeshVirtualServiceInMesh,
		SourceResourceID: "arn:aws:appmesh:us-east-1:123456789012:mesh/m/virtualService/s.apps.local",
		SourceARN:        "arn:aws:appmesh:us-east-1:123456789012:mesh/m/virtualService/s.apps.local",
		TargetResourceID: "arn:aws:appmesh:us-east-1:123456789012:mesh/m",
		TargetARN:        "arn:aws:appmesh:us-east-1:123456789012:mesh/m",
		TargetType:       catalog.ResourceTypeAppMeshMesh,
		SourceRecordID:   "arn:aws:appmesh:us-east-1:123456789012:mesh/m/virtualService/s.apps.local->arn:aws:appmesh:us-east-1:123456789012:mesh/m",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("virtualServiceRelationships() = %#v, want %#v", got, want)
	}
	if got := virtualServiceRelationships(testBoundary(), Mesh{}, svc); got != nil {
		t.Fatalf("empty mesh ARN = %#v, want nil", got)
	}
}

// TestPortParity_SiblingResourceARN freezes partition-preserving sibling
// synthesis: GovCloud partitions propagate, unknown shapes return "".
func TestPortParity_SiblingResourceARN(t *testing.T) {
	t.Parallel()
	nodeARN := "arn:aws-us-gov:appmesh:us-gov-west-1:123456789012:mesh/m/virtualNode/n"
	if got, want := siblingResourceARN(nodeARN, "virtualService", "s"),
		"arn:aws-us-gov:appmesh:us-gov-west-1:123456789012:mesh/m/virtualService/s"; got != want {
		t.Fatalf("siblingResourceARN() = %q, want %q", got, want)
	}
	if got := siblingResourceARN("arn:aws:ec2:us-east-1:123456789012:vpc/vpc-1", "virtualService", "s"); got != "" {
		t.Fatalf("siblingResourceARN(non-mesh) = %q, want empty", got)
	}
	if got := siblingResourceARN("", "virtualService", "s"); got != "" {
		t.Fatalf("siblingResourceARN(empty) = %q, want empty", got)
	}
}

// TestPortParity_VirtualNodeBackendsAndTrust freezes backend derivation
// (partition inherited from the node ARN), CA trust filtering (ARN-shaped
// only), and DNS discovery edges.
func TestPortParity_VirtualNodeBackendsAndTrust(t *testing.T) {
	t.Parallel()
	node := VirtualNode{
		ARN:                        "arn:aws:appmesh:us-east-1:123456789012:mesh/m/virtualNode/n",
		Name:                       "n",
		BackendVirtualServiceNames: []string{"s.apps.local", " ", "s.apps.local"},
		ClientTLSCertificateAuthorityARNs: []string{
			"arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/ca-1",
			"not-an-arn",
		},
		ServiceDiscoveryKind: "dns",
		DNSHostname:          "n.apps.local",
	}
	got := virtualNodeRelationships(testBoundary(), node)
	// Backends are not de-duplicated (the blank entry is skipped): 2 backend
	// edges plus trust plus DNS discovery.
	if len(got) != 4 {
		t.Fatalf("virtualNodeRelationships() produced %d edges, want 4 (2 backend + 1 trust + 1 dns)", len(got))
	}
	nodeARN := "arn:aws:appmesh:us-east-1:123456789012:mesh/m/virtualNode/n"
	backendARN := "arn:aws:appmesh:us-east-1:123456789012:mesh/m/virtualService/s.apps.local"
	if got[0].TargetResourceID != backendARN || got[0].TargetARN != backendARN {
		t.Fatalf("backend edge target = %q/%q, want %q", got[0].TargetResourceID, got[0].TargetARN, backendARN)
	}
	if got[0].RelationshipType != catalog.RelationshipAppMeshVirtualNodeBackendVirtualService {
		t.Fatalf("backend edge type = %q", got[0].RelationshipType)
	}
	if got[0].SourceRecordID != nodeARN+"->"+backendARN {
		t.Fatalf("backend record id = %q", got[0].SourceRecordID)
	}
	if got[1].TargetResourceID != backendARN {
		t.Fatalf("duplicate backend edge target = %q, want %q", got[1].TargetResourceID, backendARN)
	}
	if got[2].TargetType != catalog.ResourceTypeACMPCACertificateAuthority {
		t.Fatalf("trust edge target type = %q", got[2].TargetType)
	}
	if got[3].TargetResourceID != "n.apps.local" || got[3].RelationshipType != catalog.RelationshipAppMeshVirtualNodeUsesDNSHostname {
		t.Fatalf("dns edge = %#v", got[3])
	}
	if got := virtualNodeRelationships(testBoundary(), VirtualNode{}); got != nil {
		t.Fatalf("empty node ARN = %#v, want nil", got)
	}
}

// TestPortParity_RouteAndGatewayInMesh freezes the route-to-router and
// gateway-to-mesh edges.
func TestPortParity_RouteAndGatewayInMesh(t *testing.T) {
	t.Parallel()
	route := Route{
		ARN:              "arn:aws:appmesh:us-east-1:123456789012:mesh/m/virtualRouter/r/route/rt",
		VirtualRouterARN: "arn:aws:appmesh:us-east-1:123456789012:mesh/m/virtualRouter/r",
	}
	rels := routeRelationships(testBoundary(), route)
	if len(rels) != 1 || rels[0].TargetType != catalog.ResourceTypeAppMeshVirtualRouter {
		t.Fatalf("routeRelationships() = %#v", rels)
	}
	if rels[0].SourceRecordID != route.ARN+"->"+route.VirtualRouterARN {
		t.Fatalf("route record id = %q", rels[0].SourceRecordID)
	}
	mesh := Mesh{ARN: "arn:aws:appmesh:us-east-1:123456789012:mesh/m"}
	gw := VirtualGateway{ARN: "arn:aws:appmesh:us-east-1:123456789012:mesh/m/virtualGateway/gw"}
	grels := virtualGatewayRelationships(testBoundary(), mesh, gw)
	if len(grels) != 1 || grels[0].TargetType != catalog.ResourceTypeAppMeshMesh {
		t.Fatalf("virtualGatewayRelationships() = %#v", grels)
	}
}
