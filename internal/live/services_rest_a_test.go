// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"strings"
	"testing"
)

func lambdaResponses() map[string]string {
	return map[string]string{
		"GET /2015-03-31/functions":             `{"Functions":[{"FunctionName":"f","FunctionArn":"arn:aws:lambda:us-east-1:1:function:f"}]}`,
		"GET /2015-03-31/functions/f/aliases":   `{"Aliases":[{"AliasArn":"arn:aws:lambda:us-east-1:1:function:f:prod","Name":"prod"}]}`,
		"GET /2015-03-31/event-source-mappings": `{"EventSourceMappings":[{"UUID":"u-1","EventSourceArn":"arn:aws:sqs:us-east-1:1:queue-1"}]}`,
	}
}

func TestListLambdaReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	cfg := stubServer(t, restStub(t, lambdaResponses(), nil))

	records, err := listLambda(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listLambda error = %v", err)
	}
	want := map[string]string{
		"arn:aws:lambda:us-east-1:1:function:f":      "f",
		"arn:aws:lambda:us-east-1:1:function:f:prod": "prod",
		"arn:aws:sqs:us-east-1:1:queue-1":            "u-1",
	}
	if len(records) != len(want) {
		t.Fatalf("len(records) = %d, want %d (%v)", len(records), len(want), records)
	}
	for _, record := range records {
		if want[record.ID] != record.Name {
			t.Errorf("record %q name = %q, want %q", record.ID, record.Name, want[record.ID])
		}
	}

	for _, tc := range []struct{ prefix, wrap string }{
		{"/2015-03-31/functions", "lambda list functions"},
		{"/2015-03-31/functions/f/aliases", "lambda list aliases"},
		{"/2015-03-31/event-source-mappings", "lambda list event source mappings"},
	} {
		cfg := stubServer(t, restStub(t, lambdaResponses(), map[string]bool{tc.prefix: true}))
		if _, err := listLambda(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.wrap) {
			t.Errorf("%s: error = %v, want %q", tc.prefix, err, tc.wrap)
		}
	}
}

func eksResponses() map[string]string {
	return map[string]string{
		"GET /clusters":                    `{"clusters":["c1"]}`,
		"GET /clusters/c1":                 `{"cluster":{"name":"c1","arn":"arn:eks:c1"}}`,
		"GET /clusters/c1/node-groups":     `{"nodegroups":["ng1"]}`,
		"GET /clusters/c1/node-groups/ng1": `{"nodegroup":{"nodegroupName":"ng1","nodegroupArn":"arn:eks:ng1"}}`,
		"GET /clusters/c1/addons":          `{"addons":["vpc-cni"]}`,
		"GET /clusters/c1/addons/vpc-cni":  `{"addon":{"addonName":"vpc-cni","addonArn":"arn:eks:ad"}}`,
	}
}

func TestListEKSReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	cfg := stubServer(t, restStub(t, eksResponses(), nil))

	records, err := listEKS(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listEKS error = %v", err)
	}
	want := map[string]string{
		"arn:eks:c1":  "c1",
		"arn:eks:ng1": "ng1",
		"arn:eks:ad":  "vpc-cni",
	}
	if len(records) != len(want) {
		t.Fatalf("len(records) = %d, want %d (%v)", len(records), len(want), records)
	}
	for _, record := range records {
		if want[record.ID] != record.Name {
			t.Errorf("record %q name = %q, want %q", record.ID, record.Name, want[record.ID])
		}
	}

	for _, tc := range []struct{ prefix, wrap string }{
		{"/clusters", "eks list clusters"},
		{"/clusters/c1", "eks describe cluster"},
		{"/clusters/c1/node-groups", "eks list nodegroups"},
		{"/clusters/c1/node-groups/ng1", "eks describe nodegroup"},
		{"/clusters/c1/addons", "eks list addons"},
		{"/clusters/c1/addons/vpc-cni", "eks describe addon"},
	} {
		cfg := stubServer(t, restStub(t, eksResponses(), map[string]bool{tc.prefix: true}))
		if _, err := listEKS(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.wrap) {
			t.Errorf("%s: error = %v, want %q", tc.prefix, err, tc.wrap)
		}
	}
}
