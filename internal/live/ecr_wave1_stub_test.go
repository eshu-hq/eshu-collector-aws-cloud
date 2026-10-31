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

// wave1ECRStubConfig serves the shared ECR fixture rows as ECR JSON-protocol
// responses. It serializes the same fixture bytes the in-tree oracle
// unmarshals directly, so a stub shape bug shows as a satellite miss (fix the
// stub), never as a production edit.
func wave1ECRStubConfig(t *testing.T, fixture wave1ECRFixture) aws.Config {
	t.Helper()

	byARN := map[string]wave1ECRRow{}
	byName := map[string]wave1ECRRow{}
	for _, repository := range fixture.Repositories {
		byARN[repository.ARN] = repository
		byName[repository.Name] = repository
	}
	imagesByRepo := map[string][]wave1ECRImage{}
	for _, image := range fixture.Images {
		imagesByRepo[image.RepositoryName] = append(imagesByRepo[image.RepositoryName], image)
	}
	policiesByRepo := map[string]wave1ECRPolicy{}
	for _, policy := range fixture.Policies {
		policiesByRepo[policy.RepositoryName] = policy
	}

	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal stub response: %v", err)
		}
		return string(raw)
	}
	repositoryDoc := func(row wave1ECRRow) map[string]any {
		doc := map[string]any{
			"repositoryArn": row.ARN, "registryId": row.RegistryID,
			"repositoryName": row.Name, "repositoryUri": row.URI,
			"imageTagMutability":         row.ImageTagMutability,
			"imageScanningConfiguration": map[string]any{"scanOnPush": row.ScanOnPush},
		}
		// A zero fixture time exercises the absent-field path: the API shape
		// carries no value and both sides map it to nil.
		if !row.CreatedAt.IsZero() {
			doc["createdAt"] = float64(row.CreatedAt.Unix())
		}
		if row.EncryptionType != "" {
			encryption := map[string]any{"encryptionType": row.EncryptionType}
			if row.KMSKey != "" {
				encryption["kmsKey"] = row.KMSKey
			}
			doc["encryptionConfiguration"] = encryption
		}
		return doc
	}
	imageDoc := func(row wave1ECRImage) map[string]any {
		doc := map[string]any{
			"registryId": row.RegistryID, "repositoryName": row.RepositoryName,
			"imageDigest": row.ImageDigest, "imageSizeInBytes": row.ImageSizeInBytes,
			"imageManifestMediaType": row.ManifestMediaType,
			"artifactMediaType":      row.ArtifactMediaType,
		}
		// DescribeImages carries no separate manifest digest: the in-tree
		// adapter and the satellite both fall back to the image digest, so
		// the fixture ManifestDigest (post-mapper shape) equals it.
		if len(row.Tags) != 0 {
			doc["imageTags"] = row.Tags
		}
		if !row.PushedAt.IsZero() {
			doc["imagePushedAt"] = float64(row.PushedAt.Unix())
		}
		return doc
	}
	policyDoc := func(row wave1ECRPolicy) map[string]any {
		doc := map[string]any{
			"repositoryName": row.RepositoryName, "registryId": row.RegistryID,
			"lifecyclePolicyText": row.PolicyText,
		}
		if !row.LastEvaluatedAt.IsZero() {
			doc["lastEvaluatedAt"] = float64(row.LastEvaluatedAt.Unix())
		}
		return doc
	}
	bodyField := func(r *http.Request, field string) string {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read stub request: %v", err)
			return ""
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Errorf("decode stub request: %v", err)
			return ""
		}
		value, ok := doc[field].(string)
		if !ok {
			return ""
		}
		return value
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve := func(body string) {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write stub response: %v", err)
			}
		}
		target := r.Header.Get("X-Amz-Target")
		switch {
		case strings.HasSuffix(target, "DescribeRepositories"):
			repositories := make([]map[string]any, 0, len(fixture.Repositories))
			for _, row := range fixture.Repositories {
				repositories = append(repositories, repositoryDoc(row))
			}
			serve(encode(map[string]any{"repositories": repositories}))
		case strings.HasSuffix(target, "ListTagsForResource"):
			row, ok := byARN[bodyField(r, "resourceArn")]
			if !ok {
				t.Errorf("unknown repository ARN in ListTagsForResource")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			tags := make([]map[string]any, 0, len(row.Tags))
			for key, value := range row.Tags {
				tags = append(tags, map[string]any{"Key": key, "Value": value})
			}
			serve(encode(map[string]any{"tags": tags}))
		case strings.HasSuffix(target, "DescribeImages"):
			name := bodyField(r, "repositoryName")
			if _, ok := byName[name]; !ok {
				t.Errorf("unknown repository %q in DescribeImages", name)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			details := []map[string]any{}
			for _, row := range imagesByRepo[name] {
				details = append(details, imageDoc(row))
			}
			serve(encode(map[string]any{"imageDetails": details}))
		case strings.HasSuffix(target, "GetLifecyclePolicy"):
			name := bodyField(r, "repositoryName")
			row, ok := policiesByRepo[name]
			if !ok {
				w.Header().Set("X-Amzn-ErrorType", "LifecyclePolicyNotFoundException")
				w.WriteHeader(http.StatusBadRequest)
				serve(encode(map[string]any{"message": "Lifecycle policy not found for " + name}))
				return
			}
			serve(encode(policyDoc(row)))
		default:
			t.Errorf("unexpected ECR target %q", target)
			w.WriteHeader(http.StatusBadRequest)
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
