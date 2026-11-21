// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
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

// wave1SSMStubBulkTarget is the JSON-protocol target the pinned SDK sends for
// Resource Groups Tagging API GetResources calls.
const wave1SSMStubBulkTarget = "ResourceGroupsTaggingAPI_20170126.GetResources"

// wave1SSMStubCalls counts stubbed API hits per server. ListTags must stay
// zero in every stub-driven test: the bulk lane performs zero
// ListTagsForResource calls by contract (decision 3.3 call-count gate).
type wave1SSMStubCalls struct {
	Describe     atomic.Int64
	ListTags     atomic.Int64
	GetResources atomic.Int64
}

// wave1SSMStubOpt reshapes the bulk half of the stub for one leg-failure or
// pagination gate. The zero value serves the fixture tags as a single bulk
// page.
type wave1SSMStubOpt func(*wave1SSMStubBulkShape)

// wave1SSMStubBulkShape scripts GetResources responses. Pages are served in
// order against the PaginationToken sequence "", "wave1-bulk-page-1", ...;
// status non-zero fails every bulk page with the given JSON-protocol error.
type wave1SSMStubBulkShape struct {
	pages      [][]map[string]any
	status     int
	errorType  string
	errorValue string
}

// withSSMStubBulkPages serves the given ResourceTagMapping pages in token
// order instead of the default single fixture page.
func withSSMStubBulkPages(pages ...[]map[string]any) wave1SSMStubOpt {
	return func(shape *wave1SSMStubBulkShape) {
		shape.pages = pages
	}
}

// withSSMStubBulkError fails every GetResources page with the given
// JSON-protocol error shape (throttle and denial gates).
func withSSMStubBulkError(status int, errorType, errorValue string) wave1SSMStubOpt {
	return func(shape *wave1SSMStubBulkShape) {
		shape.status = status
		shape.errorType = errorType
		shape.errorValue = errorValue
	}
}

// wave1SSMStubConfig serves the shared SSM fixture rows as SSM JSON-protocol
// responses plus a Resource Groups Tagging API bulk page carrying the fixture
// tags. It serializes the same fixture bytes the in-tree oracle unmarshals
// directly, so a stub shape bug shows as a satellite miss (fix the stub),
// never as a production edit. Any per-parameter ListTagsForResource call is a
// contract violation: the stub records it and fails the request.
func wave1SSMStubConfig(t *testing.T, fixture wave1SSMFixture, opts ...wave1SSMStubOpt) (aws.Config, *wave1SSMStubCalls) {
	t.Helper()

	shape := &wave1SSMStubBulkShape{}
	for _, opt := range opts {
		opt(shape)
	}
	if shape.pages == nil {
		shape.pages = [][]map[string]any{wave1SSMStubDefaultMappings(fixture)}
	}

	byName := map[string]wave1SSMParameterRow{}
	for _, parameter := range fixture.Parameters {
		byName[parameter.Name] = parameter
	}

	calls := &wave1SSMStubCalls{}
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
			calls.Describe.Add(1)
			parameters := make([]map[string]any, 0, len(fixture.Parameters))
			for _, row := range fixture.Parameters {
				parameters = append(parameters, parameterDoc(row))
			}
			serve(encode(map[string]any{"Parameters": parameters}))
		case "AmazonSSM.ListTagsForResource":
			calls.ListTags.Add(1)
			t.Errorf("bulk lane must not call ListTagsForResource")
			w.WriteHeader(http.StatusBadRequest)
		case wave1SSMStubBulkTarget:
			calls.GetResources.Add(1)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read stub request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var input struct {
				ResourceTypeFilters []string
				ResourcesPerPage    *int32
				PaginationToken     *string
			}
			if err := json.Unmarshal(body, &input); err != nil {
				t.Errorf("decode stub request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// The S-F shim proved the ssm:parameter filter at 100/page:
			// the stub pins both so a production drift fails loudly.
			if !reflect.DeepEqual(input.ResourceTypeFilters, []string{"ssm:parameter"}) {
				t.Errorf("bulk ResourceTypeFilters = %#v, want [ssm:parameter]", input.ResourceTypeFilters)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if input.ResourcesPerPage == nil || *input.ResourcesPerPage != 100 {
				t.Errorf("bulk ResourcesPerPage = %#v, want 100", input.ResourcesPerPage)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if shape.status != 0 {
				w.WriteHeader(shape.status)
				serve(encode(map[string]any{"__type": shape.errorType, "message": shape.errorValue}))
				return
			}
			index := 0
			if token := aws.ToString(input.PaginationToken); token != "" {
				var parsed int
				if _, err := fmt.Sscanf(token, "wave1-bulk-page-%d", &parsed); err != nil || parsed < 1 || parsed >= len(shape.pages) {
					t.Errorf("unexpected bulk PaginationToken %q", token)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				index = parsed
			}
			response := map[string]any{"ResourceTagMappingList": shape.pages[index]}
			if index+1 < len(shape.pages) {
				response["PaginationToken"] = fmt.Sprintf("wave1-bulk-page-%d", index+1)
			}
			serve(encode(response))
		default:
			t.Errorf("unexpected target %q", r.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	return aws.Config{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	}, calls
}

// wave1SSMStubDefaultMappings serves every tagged fixture row as one bulk
// entry. The ARN-less row joins under its constructed ARN (the tagging API
// always keys by ARN); the untagged row stays absent (untagged-by-absence).
// The padded tag key rides through verbatim so the trim mapping stays pinned.
func wave1SSMStubDefaultMappings(fixture wave1SSMFixture) []map[string]any {
	mappings := []map[string]any{}
	for _, row := range fixture.Parameters {
		if len(row.Tags) == 0 {
			continue
		}
		arn := row.ARN
		if arn == "" {
			arn = "arn:aws:ssm:us-east-1:123456789012:parameter" + row.Name
		}
		tags := []map[string]any{}
		for key, value := range row.Tags {
			tags = append(tags, map[string]any{"Key": key, "Value": value})
		}
		mappings = append(mappings, map[string]any{"ResourceARN": arn, "Tags": tags})
	}
	return mappings
}

// wave1SSMStubMapping builds one bulk entry for scripted pages.
func wave1SSMStubMapping(arn string, tags map[string]string) map[string]any {
	list := []map[string]any{}
	for key, value := range tags {
		list = append(list, map[string]any{"Key": key, "Value": value})
	}
	return map[string]any{"ResourceARN": arn, "Tags": list}
}
