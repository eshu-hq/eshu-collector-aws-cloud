// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// TestListECRDescribeImagesPassesRegistryID pins the in-tree DescribeImages
// fidelity the shared wave-1 fixture cannot see: the in-tree adapter sends
// RegistryId whenever the repository carries one
// (service/ecr/awssdk/client.go), so cross-account repositories resolve to
// the owning registry. All fixture registries equal the caller account, so
// the oracle parity stays green either way; this test fails while listECR
// builds DescribeImagesInput from the repository name alone.
func TestListECRDescribeImagesPassesRegistryID(t *testing.T) {
	t.Parallel()

	const registryID = "123456789012"
	var gotRegistryID *string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve := func(body string) {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write stub response: %v", err)
			}
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read stub request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Errorf("decode stub request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var field string
		if value, ok := doc["registryId"].(string); ok {
			field = value
		}
		switch target := r.Header.Get("X-Amz-Target"); {
		case strings.HasSuffix(target, "DescribeRepositories"):
			serve(`{"repositories":[{"repositoryArn":"arn:aws:ecr:us-east-1:` + registryID + `:repository/wave1-x","registryId":"` + registryID + `","repositoryName":"wave1-x","repositoryUri":"` + registryID + `.dkr.ecr.us-east-1.amazonaws.com/wave1-x","imageTagMutability":"MUTABLE"}]}`)
		case strings.HasSuffix(target, "ListTagsForResource"):
			serve(`{"tags":[]}`)
		case strings.HasSuffix(target, "DescribeImages"):
			gotRegistryID = &field
			serve(`{"imageDetails":[{"repositoryName":"wave1-x","registryId":"` + registryID + `","imageDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","imageTags":["latest"]}]}`)
		case strings.HasSuffix(target, "GetLifecyclePolicy"):
			w.Header().Set("X-Amzn-ErrorType", "LifecyclePolicyNotFoundException")
			w.WriteHeader(http.StatusBadRequest)
			serve(`{"message":"Lifecycle policy not found for wave1-x"}`)
		default:
			t.Errorf("unexpected ECR target %q", target)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	cfg := aws.Config{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	}

	records, err := listECR(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if gotRegistryID == nil {
		t.Fatal("DescribeImages was never called")
	}
	if *gotRegistryID != registryID {
		t.Fatalf("DescribeImages registryId = %q, want %q", *gotRegistryID, registryID)
	}
	found := false
	for _, record := range records {
		if ref := record.ImageReference; ref != nil && ref.Tag == "latest" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected latest image reference missing")
	}
}
