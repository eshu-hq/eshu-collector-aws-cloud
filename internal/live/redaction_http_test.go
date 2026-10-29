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
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/eshu-hq/eshu-sdk/collector/marker"
)

func TestLambdaGetFunctionHTTPRedactsEnvironment(t *testing.T) {
	const arn = "arn:aws:lambda:us-east-1:123456789012:function:worker"
	const rawPassword = "raw-password-canary"
	const rawOrdinary = "raw-ordinary-canary"
	const rawLocation = "raw-location-canary"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/2015-03-31/functions":
			fmt.Fprintf(w, `{"Functions":[{"FunctionName":"worker","FunctionArn":%q}]}`, arn)
		case "/2015-03-31/functions/" + arn:
			fmt.Fprintf(w, `{"Configuration":{"FunctionName":"worker","FunctionArn":%q,"Environment":{"Variables":{"PASSWORD":%q,"PLAIN":%q,"EMPTY":""}}},"Code":{"Location":%q}}`, arn, rawPassword, rawOrdinary, "https://download.example/?token="+rawLocation)
		case "/2015-03-31/functions/" + arn + "/aliases", "/2015-03-31/event-source-mappings":
			fmt.Fprint(w, `{}`)
		default:
			t.Errorf("unexpected Lambda request path %q", request.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	cfg := aws.Config{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	}
	key := testRedactionKey()
	records, err := listLambda(context.Background(), cfg, key)
	if err != nil {
		t.Fatalf("Lambda SDK read failed: %v", err)
	}
	if len(records) != 1 || records[0].Resource == nil {
		t.Fatalf("Lambda SDK records: count=%d", len(records))
	}
	environment := records[0].Resource.Attributes["environment"].(map[string]any)
	for name, raw := range map[string]string{"PASSWORD": rawPassword, "PLAIN": rawOrdinary, "EMPTY": ""} {
		reason := "unknown_provider_schema"
		if name == "PASSWORD" {
			reason = "known_sensitive_key"
		}
		source := "lambda.function.environment." + name
		want := marker.String(raw, reason, source, key)
		got := environment[name].(map[string]any)
		if len(got) != 4 || got["marker"] != want.Marker || got["reason"] != want.Reason || got["source"] != want.Source || got["ruleset_version"] != awsRedactionRuleset {
			t.Fatalf("Lambda %s marker mismatch: %#v", name, got)
		}
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{rawPassword, rawOrdinary, rawLocation, "download.example"} {
		if strings.Contains(string(encoded), canary) {
			t.Fatalf("Lambda SDK record contains forbidden canary %q", canary)
		}
	}
}

func TestLambdaGetFunctionErrorDoesNotEchoResponseCanary(t *testing.T) {
	const arn = "arn:aws:lambda:us-east-1:123456789012:function:worker"
	const canary = "raw-error-canary"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/2015-03-31/functions" {
			fmt.Fprintf(w, `{"Functions":[{"FunctionName":"worker","FunctionArn":%q}]}`, arn)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"__type":"InvalidParameterValueException","Message":%q}`, canary)
	}))
	defer server.Close()
	cfg := aws.Config{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	}
	records, err := listLambda(context.Background(), cfg, testRedactionKey())
	if err == nil || len(records) != 0 || strings.Contains(err.Error(), canary) || !strings.Contains(err.Error(), "InvalidParameterValueException") {
		t.Fatalf("Lambda error exposed response canary: records=%d err=%v", len(records), err)
	}
	reader := Collector{LoadConfig: func(context.Context, string) (aws.Config, error) { return cfg, nil },
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
	}
	_, err = reader.CollectReport(context.Background(), Config{AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"lambda"}, RedactionKey: testRedactionKey()})
	if err == nil || strings.Contains(err.Error(), canary) {
		t.Fatalf("Lambda collection status exposed response canary: %v", err)
	}
}

func TestECSDescribeTaskDefinitionErrorDoesNotEchoResponseCanary(t *testing.T) {
	const arn = "arn:aws:ecs:us-east-1:123456789012:task-definition/web:1"
	const canary = "raw-ecs-error-canary"
	transport := ecsRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		operation := request.Header.Get("X-Amz-Target")
		operation = operation[strings.LastIndex(operation, ".")+1:]
		code, body := http.StatusOK, `{}`
		switch operation {
		case "ListClusters":
			body = `{"clusterArns":[]}`
		case "ListTaskDefinitions":
			body = fmt.Sprintf(`{"taskDefinitionArns":[%q]}`, arn)
		case "DescribeTaskDefinition":
			code = http.StatusBadRequest
			body = fmt.Sprintf(`{"__type":"InvalidParameterException","message":%q}`, canary)
		default:
			t.Errorf("unexpected ECS operation %s", operation)
		}
		return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})
	cfg := aws.Config{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}, RetryMaxAttempts: 1}
	records, err := listECS(context.Background(), cfg, testRedactionKey())
	if err == nil || len(records) != 0 || strings.Contains(err.Error(), canary) || !strings.Contains(err.Error(), "InvalidParameterException") {
		t.Fatalf("ECS error exposed response canary: records=%d err=%v", len(records), err)
	}
	reader := Collector{LoadConfig: func(context.Context, string) (aws.Config, error) { return cfg, nil },
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
	}
	_, err = reader.CollectReport(context.Background(), Config{AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"ecs"}, RedactionKey: testRedactionKey()})
	if err == nil || strings.Contains(err.Error(), canary) {
		t.Fatalf("ECS collection status exposed response canary: %v", err)
	}
}
