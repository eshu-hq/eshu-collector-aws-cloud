// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestEKSOIDCListDenialKeepsClustersAndWarns(t *testing.T) {
	for _, code := range []string{"AccessDenied", "Throttling"} {
		t.Run(code, func(t *testing.T) {
			cfg, calls := eksOIDCTestConfig(t, code, "")
			reader := Collector{
				LoadConfig: func(context.Context, string) (aws.Config, error) { return cfg, nil },
				VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
					return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
				},
				Loaders: map[string]Loader{"eks": listEKS},
			}
			out, err := reader.CollectReport(context.Background(), Config{AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"eks"}})
			if code == "Throttling" {
				if err == nil || len(out.Resources) != 0 {
					t.Fatalf("non-denial must be terminal: resources=%d err=%v", len(out.Resources), err)
				}
				return
			}
			if err != nil || len(out.Resources) != 4 || len(out.WarningObservations) != 1 || len(out.Warnings) != 1 {
				t.Fatalf("partial EKS result: resources=%d warnings=%v observations=%v err=%v", len(out.Resources), out.Warnings, out.WarningObservations, err)
			}
			warning := out.WarningObservations[0]
			if warning.Attributes["operation"] != "ListOpenIDConnectProviders" || warning.Attributes["resource"] != "region:us-east-1" || warning.Boundary.ServiceKind != "eks" {
				t.Fatalf("warning identity = %+v", warning)
			}
			if (*calls)["ListOpenIDConnectProviders"] != 1 || (*calls)["ListNodegroups"] != 2 || (*calls)["ListAddons"] != 2 {
				t.Fatalf("read coverage = %v", *calls)
			}
			var clusters, issuerProviders int
			for _, row := range out.Resources {
				switch row.ResourceType {
				case "aws_eks_cluster":
					clusters++
					provider, ok := row.Attributes["oidc_provider"].(map[string]any)
					if !ok || provider["arn"] != "" {
						t.Fatalf("unverified provider on %s: %v", row.ResourceID, provider)
					}
				case "aws_eks_oidc_provider":
					issuerProviders++
					if row.ARN != "" || row.ResourceID != "https://issuer.example.invalid/id/demo" {
						t.Fatalf("issuer-only provider must not assert IAM match: %+v", row)
					}
				}
			}
			if clusters != 2 || issuerProviders != 2 || len(out.Relationships) != 2 {
				t.Fatalf("issuer fallback coverage: clusters=%d providers=%d edges=%d", clusters, issuerProviders, len(out.Relationships))
			}
		})
	}
}

func TestEKSOIDCNoMatchRetainsIssuerResource(t *testing.T) {
	cfg, calls := eksOIDCTestConfig(t, "NoMatch", "")
	records, err := listEKS(context.Background(), cfg, VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	var clusters, providers, edges int
	for _, row := range records {
		if row.Resource == nil {
			continue
		}
		switch row.Resource.ResourceType {
		case "aws_eks_cluster":
			clusters++
			for _, edge := range row.Relationships {
				if edge.RelationshipType == "eks_cluster_has_oidc_provider" && edge.TargetARN == "" && edge.TargetResourceID == "https://issuer.example.invalid/id/demo" {
					edges++
				}
			}
		case "aws_eks_oidc_provider":
			providers++
			if row.Resource.ARN != "" || row.Resource.ResourceID != "https://issuer.example.invalid/id/demo" {
				t.Fatalf("unexpected IAM assertion: %+v", row.Resource)
			}
		}
	}
	if clusters != 2 || providers != 2 || edges != 2 || (*calls)["GetOpenIDConnectProvider"] != 0 {
		t.Fatalf("issuer-only fallback: clusters=%d providers=%d edges=%d calls=%v", clusters, providers, edges, *calls)
	}
}

func TestEKSOIDCGetDenialRemainsTerminal(t *testing.T) {
	cfg, calls := eksOIDCTestConfig(t, "", "AccessDenied")
	records, err := listEKS(context.Background(), cfg, VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err == nil || len(records) != 0 || (*calls)["GetOpenIDConnectProvider"] != 1 {
		t.Fatalf("Get failure must be terminal: records=%d calls=%v err=%v", len(records), *calls, err)
	}
}

func TestEKSOIDCEnrichmentMatchesIssuerAndCachesPerRead(t *testing.T) {
	cfg, calls := eksOIDCTestConfig(t, "", "")
	records, err := listEKS(context.Background(), cfg, VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if (*calls)["ListOpenIDConnectProviders"] != 1 || (*calls)["GetOpenIDConnectProvider"] != 1 {
		t.Fatalf("IAM calls=%v, want one list and get across clusters", *calls)
	}
	var clusters, providerRows, edges int
	for _, row := range records {
		if row.Resource != nil && row.Resource.ResourceType == "aws_eks_oidc_provider" {
			providerRows++
			if row.Resource.Attributes["issuer_url"] != "https://issuer.example.invalid/id/demo" {
				t.Fatalf("OIDC provider resource = %+v", row.Resource)
			}
		}
		if row.Resource == nil || row.Resource.ResourceType != "aws_eks_cluster" {
			continue
		}
		clusters++
		for _, edge := range row.Relationships {
			if edge.RelationshipType == "eks_cluster_has_oidc_provider" {
				edges++
			}
		}
		provider, ok := row.Resource.Attributes["oidc_provider"].(map[string]any)
		if !ok || provider["arn"] != "arn:aws:iam::123456789012:oidc-provider/issuer.example.invalid/id/demo" || provider["issuer_url"] != "https://issuer.example.invalid/id/demo" {
			t.Fatalf("provider enrichment = %v", provider)
		}
	}
	if clusters != 2 || providerRows != 2 || edges != 2 {
		t.Fatalf("EKS OIDC coverage: clusters=%d providers=%d edges=%d", clusters, providerRows, edges)
	}
}

func eksOIDCTestConfig(t *testing.T, listError, getError string) (aws.Config, *map[string]int) {
	t.Helper()
	calls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve := func(body string) {
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write fixture response: %v", err)
			}
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		action := r.Form.Get("Action")
		if action == "" {
			switch {
			case r.URL.Path == "/clusters":
				action = "ListClusters"
			case strings.HasSuffix(r.URL.Path, "/node-groups"):
				action = "ListNodegroups"
			case strings.HasSuffix(r.URL.Path, "/addons"):
				action = "ListAddons"
			case strings.HasPrefix(r.URL.Path, "/clusters/"):
				action = "DescribeCluster"
			}
		}
		calls[action]++
		if action == "ListOpenIDConnectProviders" || action == "GetOpenIDConnectProvider" {
			w.Header().Set("Content-Type", "text/xml")
			code := getError
			if action == "ListOpenIDConnectProviders" {
				code = listError
				if code == "NoMatch" {
					code = ""
				}
			}
			if code != "" {
				w.WriteHeader(http.StatusForbidden)
				serve(fmt.Sprintf(`<ErrorResponse><Error><Code>%s</Code><Message>denied</Message></Error></ErrorResponse>`, code))
				return
			}
			if action == "ListOpenIDConnectProviders" {
				if listError == "NoMatch" {
					serve(`<ListOpenIDConnectProvidersResponse><ListOpenIDConnectProvidersResult><OpenIDConnectProviderList/></ListOpenIDConnectProvidersResult></ListOpenIDConnectProvidersResponse>`)
					return
				}
				serve(`<ListOpenIDConnectProvidersResponse><ListOpenIDConnectProvidersResult><OpenIDConnectProviderList><member><Arn>arn:aws:iam::123456789012:oidc-provider/issuer.example.invalid/id/demo</Arn></member></OpenIDConnectProviderList></ListOpenIDConnectProvidersResult></ListOpenIDConnectProvidersResponse>`)
			} else {
				serve(`<GetOpenIDConnectProviderResponse><GetOpenIDConnectProviderResult><Url>issuer.example.invalid/id/demo</Url><ClientIDList><member>sts.amazonaws.com</member></ClientIDList><ThumbprintList><member>abc123</member></ThumbprintList></GetOpenIDConnectProviderResult></GetOpenIDConnectProviderResponse>`)
			}
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch action {
		case "ListClusters":
			serve(`{"clusters":["one","two"]}`)
		case "DescribeCluster":
			serve(`{"cluster":{"name":"one","arn":"arn:aws:eks:us-east-1:123456789012:cluster/one","identity":{"oidc":{"issuer":"https://issuer.example.invalid/id/demo"}}}}`)
		case "ListNodegroups":
			serve(`{"nodegroups":[]}`)
		case "ListAddons":
			serve(`{"addons":[]}`)
		default:
			t.Errorf("unexpected AWS action %q", action)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	return aws.Config{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	}, &calls
}
