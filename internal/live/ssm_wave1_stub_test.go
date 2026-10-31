// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// wave1SSMStubDescriptionText and wave1SSMStubPatternText stand in for the
// raw user-authored description and allowed pattern the API returns: both
// sides map them to presence booleans only, and the payload-branches test
// proves neither string ever enters a fact. wave1SSMStubPolicyText does the
// same for policy JSON text, which neither side reads.
const (
	wave1SSMStubDescriptionText = "wave1-present-description"
	wave1SSMStubPatternText     = "wave1-present-pattern"
	wave1SSMStubPolicyText      = "wave1-policy-json-must-not-emit"
)

// wave1SSMStubConfig serves the shared SSM fixture rows as SSM JSON-protocol
// responses. It serializes the same fixture bytes the in-tree oracle
// unmarshals directly, so a stub shape bug shows as a satellite miss (fix
// the stub), never as a production edit.
func wave1SSMStubConfig(t *testing.T, fixture wave1SSMFixture) aws.Config {
	t.Helper()

	byName := map[string]wave1SSMParameterRow{}
	for _, parameter := range fixture.Parameters {
		byName[parameter.Name] = parameter
	}

	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal stub response: %v", err)
		}
		return string(raw)
	}
	parameterDoc := func(row wave1SSMParameterRow) map[string]any {
		doc := map[string]any{
			"Name": row.Name, "Type": row.Type, "Tier": row.Tier,
			"DataType": row.DataType, "KeyId": row.KeyID,
		}
		// An ARN-less fixture row exercises the name-fallback path: the API
		// shape carries no value and both sides fall back to the name.
		if row.ARN != "" {
			doc["ARN"] = row.ARN
		}
		// A zero fixture time exercises the absent-field path: the API shape
		// carries no value and both sides map it to nil.
		if !row.LastModifiedAt.IsZero() {
			doc["LastModifiedDate"] = float64(row.LastModifiedAt.Unix())
		}
		// Raw text rides the DescribeParameters response only: both sides
		// keep presence booleans, and the payload-branches test proves the
		// text itself never enters a fact.
		if row.DescriptionPresent {
			doc["Description"] = wave1SSMStubDescriptionText
		}
		if row.AllowedPatternPresent {
			doc["AllowedPattern"] = wave1SSMStubPatternText
		}
		policies := []map[string]any{}
		for _, policy := range row.Policies {
			policies = append(policies, map[string]any{
				"PolicyType": policy.Type, "PolicyStatus": policy.Status,
				"PolicyText": wave1SSMStubPolicyText,
			})
		}
		doc["Policies"] = policies
		return doc
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve := func(body string) {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write stub response: %v", err)
			}
		}
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonSSM.DescribeParameters":
			parameters := make([]map[string]any, 0, len(fixture.Parameters))
			for _, row := range fixture.Parameters {
				parameters = append(parameters, parameterDoc(row))
			}
			serve(encode(map[string]any{"Parameters": parameters}))
		case "AmazonSSM.ListTagsForResource":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read stub request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var input struct {
				ResourceId string
			}
			if err := json.Unmarshal(body, &input); err != nil {
				t.Errorf("decode stub request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			row, ok := byName[input.ResourceId]
			if !ok {
				t.Errorf("unknown parameter %q", input.ResourceId)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			tags := []map[string]any{}
			for key, value := range row.Tags {
				tags = append(tags, map[string]any{"Key": key, "Value": value})
			}
			serve(encode(map[string]any{"TagList": tags}))
		default:
			t.Errorf("unexpected SSM target %q", r.Header.Get("X-Amz-Target"))
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
