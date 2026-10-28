// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"strings"
	"testing"
)

func TestListSSMReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	responses := map[string]string{
		"AmazonSSM.DescribeParameters": `{"Parameters":[{"Name":"/app/key"}]}`,
	}
	cfg := stubServer(t, jsonStub(t, responses, nil))

	records, err := listSSM(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listSSM error = %v", err)
	}
	if len(records) != 1 || records[0].Name != "/app/key" {
		t.Fatalf("records = %v, want the stubbed parameter", records)
	}

	cfg = stubServer(t, jsonStub(t, responses, map[string]bool{"AmazonSSM.DescribeParameters": true}))
	if _, err := listSSM(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "ssm describe parameters") {
		t.Fatalf("denied DescribeParameters: error = %v, want ssm describe parameters", err)
	}
}

func TestListSecretsManagerReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	responses := map[string]string{
		"secretsmanager.ListSecrets": `{"SecretList":[{"ARN":"arn:aws:secretsmanager:us-east-1:1:secret:s1","Name":"s1"}]}`,
	}
	cfg := stubServer(t, jsonStub(t, responses, nil))

	records, err := listSecretsManager(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listSecretsManager error = %v", err)
	}
	if len(records) != 1 || records[0].ID != "arn:aws:secretsmanager:us-east-1:1:secret:s1" || records[0].Name != "s1" {
		t.Fatalf("records = %v, want the stubbed secret", records)
	}

	cfg = stubServer(t, jsonStub(t, responses, map[string]bool{"secretsmanager.ListSecrets": true}))
	if _, err := listSecretsManager(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "secretsmanager list secrets") {
		t.Fatalf("denied ListSecrets: error = %v, want secretsmanager list secrets", err)
	}
}

func TestListCloudWatchLogsReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	responses := map[string]string{
		"Logs_20140328.DescribeLogGroups": `{"logGroups":[{"logGroupName":"g1","arn":"arn:aws:logs:us-east-1:1:log-group:g1"}]}`,
	}
	cfg := stubServer(t, jsonStub(t, responses, nil))

	records, err := listCloudWatchLogs(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listCloudWatchLogs error = %v", err)
	}
	if len(records) != 1 || records[0].Name != "g1" {
		t.Fatalf("records = %v, want the stubbed log group", records)
	}

	cfg = stubServer(t, jsonStub(t, responses, map[string]bool{"Logs_20140328.DescribeLogGroups": true}))
	if _, err := listCloudWatchLogs(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "cloudwatchlogs describe log groups") {
		t.Fatalf("denied DescribeLogGroups: error = %v, want cloudwatchlogs describe log groups", err)
	}
}

func eventsResponses() map[string]string {
	return map[string]string{
		"AWSEvents.ListEventBuses": `{"EventBuses":[{"Name":"default","Arn":"arn:aws:events:us-east-1:1:event-bus/default"}]}`,
		"AWSEvents.ListRules":      `{"Rules":[{"Name":"r1","Arn":"arn:aws:events:us-east-1:1:rule/default/r1"}]}`,
	}
}

func TestListEventBridgeReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	cfg := stubServer(t, jsonStub(t, eventsResponses(), nil))

	records, err := listEventBridge(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listEventBridge error = %v", err)
	}
	want := map[string]string{
		"arn:aws:events:us-east-1:1:event-bus/default": "default",
		"arn:aws:events:us-east-1:1:rule/default/r1":   "r1",
	}
	if len(records) != len(want) {
		t.Fatalf("len(records) = %d, want %d (%v)", len(records), len(want), records)
	}
	for _, record := range records {
		if want[record.ID] != record.Name {
			t.Errorf("record %q name = %q, want %q", record.ID, record.Name, want[record.ID])
		}
	}

	for _, tc := range []struct{ target, wrap string }{
		{"AWSEvents.ListEventBuses", "eventbridge list event buses"},
		{"AWSEvents.ListRules", "eventbridge list rules"},
	} {
		cfg := stubServer(t, jsonStub(t, eventsResponses(), map[string]bool{tc.target: true}))
		if _, err := listEventBridge(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.wrap) {
			t.Errorf("%s: error = %v, want %q", tc.target, err, tc.wrap)
		}
	}
}
