// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// wave1EKSStubConfig serves the shared EKS fixture rows as EKS REST-JSON and
// IAM query-protocol responses. It serializes the same fixture bytes the
// in-tree oracle unmarshals directly, so a stub shape bug shows as a satellite
// miss (fix the stub), never as a production edit.
func wave1EKSStubConfig(t *testing.T, fixture wave1EKSFixture) aws.Config {
	t.Helper()

	byCluster := map[string]wave1EKSClusterRow{}
	names := []string{}
	for _, cluster := range fixture.Clusters {
		byCluster[cluster.Name] = cluster
		names = append(names, cluster.Name)
	}
	nodegroupsByCluster := map[string][]string{}
	nodegroupRows := map[string]wave1EKSNodegroupRow{}
	for _, nodegroup := range fixture.Nodegroups {
		key := nodegroup.ClusterName + "/" + nodegroup.Name
		nodegroupsByCluster[nodegroup.ClusterName] = append(nodegroupsByCluster[nodegroup.ClusterName], nodegroup.Name)
		nodegroupRows[key] = nodegroup
	}
	addonsByCluster := map[string][]string{}
	addonRows := map[string]wave1EKSAddonRow{}
	for _, addon := range fixture.Addons {
		key := addon.ClusterName + "/" + addon.Name
		addonsByCluster[addon.ClusterName] = append(addonsByCluster[addon.ClusterName], addon.Name)
		addonRows[key] = addon
	}

	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal stub response: %v", err)
		}
		return string(raw)
	}
	clusterDoc := func(row wave1EKSClusterRow) string {
		cluster := map[string]any{
			"name": row.Name, "arn": row.ARN, "version": row.Version,
			"platformVersion": row.PlatformVersion, "status": row.Status,
			"endpoint": row.Endpoint, "roleArn": row.RoleARN,
			"identity": map[string]any{
				"oidc": map[string]any{"issuer": row.OIDCProvider.IssuerURL},
			},
			"resourcesVpcConfig": map[string]any{
				"vpcId": row.VPCConfig.VPCID, "subnetIds": row.VPCConfig.SubnetIDs,
				"securityGroupIds":       row.VPCConfig.SecurityGroupIDs,
				"clusterSecurityGroupId": row.VPCConfig.ClusterSecurityGroupID,
				"endpointPublicAccess":   row.VPCConfig.EndpointPublicAccess,
				"endpointPrivateAccess":  row.VPCConfig.EndpointPrivateAccess,
				"publicAccessCidrs":      row.VPCConfig.PublicAccessCIDRs,
			},
			"tags": row.Tags,
		}
		// A zero fixture time exercises the absent-field path: the API shape
		// carries no value and both sides map it to nil.
		if !row.CreatedAt.IsZero() {
			cluster["createdAt"] = float64(row.CreatedAt.Unix())
		}
		return encode(map[string]any{"cluster": cluster})
	}
	nodegroupDoc := func(row wave1EKSNodegroupRow) string {
		return encode(map[string]any{"nodegroup": map[string]any{
			"nodegroupName": row.Name, "nodegroupArn": row.ARN, "clusterName": row.ClusterName,
			"version": row.Version, "releaseVersion": row.ReleaseVersion, "status": row.Status,
			"capacityType": row.CapacityType, "amiType": row.AMIType, "instanceTypes": row.InstanceTypes,
			"subnets": row.Subnets,
			"scalingConfig": map[string]any{
				"desiredSize": row.ScalingConfig.DesiredSize, "minSize": row.ScalingConfig.MinSize,
				"maxSize": row.ScalingConfig.MaxSize,
			},
			"nodeRole": row.NodeRoleARN, "tags": row.Tags,
		}})
	}
	addonDoc := func(row wave1EKSAddonRow) string {
		addon := map[string]any{
			"addonName": row.Name, "addonArn": row.ARN, "clusterName": row.ClusterName,
			"addonVersion": row.Version, "status": row.Status,
			"serviceAccountRoleArn": row.ServiceAccountRoleARN, "tags": row.Tags,
		}
		if !row.CreatedAt.IsZero() {
			addon["createdAt"] = float64(row.CreatedAt.Unix())
		}
		if !row.ModifiedAt.IsZero() {
			addon["modifiedAt"] = float64(row.ModifiedAt.Unix())
		}
		return encode(map[string]any{"addon": addon})
	}

	// The IAM detail echoes the matched fixture provider row, so enrichment
	// values agree with the oracle inputs by construction; which provider
	// matches (and that the unmatched cluster stays issuer-only) is what the
	// key comparison proves.
	var matched wave1EKSOIDCProviderRow
	for _, cluster := range fixture.Clusters {
		if cluster.OIDCProvider.ARN != "" {
			matched = cluster.OIDCProvider
		}
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve := func(body, contentType string) {
			w.Header().Set("Content-Type", contentType)
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write stub response: %v", err)
			}
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		if action := r.Form.Get("Action"); action != "" {
			serveIAM := func(body string) { serve(body, "text/xml") }
			switch action {
			case "ListOpenIDConnectProviders":
				serveIAM(`<ListOpenIDConnectProvidersResponse><ListOpenIDConnectProvidersResult><OpenIDConnectProviderList><member><Arn>` + matched.ARN + `</Arn></member></OpenIDConnectProviderList></ListOpenIDConnectProvidersResult></ListOpenIDConnectProvidersResponse>`)
			case "GetOpenIDConnectProvider":
				serveIAM(`<GetOpenIDConnectProviderResponse><GetOpenIDConnectProviderResult><Url>` + matched.IssuerURL + `</Url><ClientIDList>` + wave1IAMMembers(matched.ClientIDs) + `</ClientIDList><ThumbprintList>` + wave1IAMMembers(matched.Thumbprints) + `</ThumbprintList></GetOpenIDConnectProviderResult></GetOpenIDConnectProviderResponse>`)
			default:
				t.Errorf("unexpected IAM action %q", action)
				w.WriteHeader(http.StatusBadRequest)
			}
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/clusters")
		switch {
		case rest == "" || rest == "/":
			serve(encode(map[string]any{"clusters": names}), "application/x-amz-json-1.1")
		case strings.Count(rest, "/") == 1:
			name := strings.TrimPrefix(rest, "/")
			row, ok := byCluster[name]
			if !ok {
				t.Errorf("unknown cluster %q", name)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			serve(clusterDoc(row), "application/x-amz-json-1.1")
		default:
			parts := strings.Split(strings.Trim(rest, "/"), "/")
			if len(parts) < 2 || len(parts) > 3 {
				t.Errorf("unexpected EKS path %q", r.URL.Path)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			name, kind := parts[0], parts[1]
			child := ""
			if len(parts) == 3 {
				child = parts[2]
			}
			switch kind {
			case "node-groups":
				if child == "" {
					serve(encode(map[string]any{"nodegroups": nodegroupsByCluster[name]}), "application/x-amz-json-1.1")
					return
				}
				row, ok := nodegroupRows[name+"/"+child]
				if !ok {
					t.Errorf("unknown nodegroup %q", name+"/"+child)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				serve(nodegroupDoc(row), "application/x-amz-json-1.1")
			case "addons":
				if child == "" {
					serve(encode(map[string]any{"addons": addonsByCluster[name]}), "application/x-amz-json-1.1")
					return
				}
				row, ok := addonRows[name+"/"+child]
				if !ok {
					t.Errorf("unknown addon %q", name+"/"+child)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				serve(addonDoc(row), "application/x-amz-json-1.1")
			default:
				t.Errorf("unexpected EKS path %q", r.URL.Path)
				w.WriteHeader(http.StatusBadRequest)
			}
		}
	}))
	t.Cleanup(server.Close)
	return aws.Config{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	}
}

func wave1IAMMembers(values []string) string {
	var out strings.Builder
	for _, value := range values {
		fmt.Fprintf(&out, "<member>%s</member>", value)
	}
	return out.String()
}
