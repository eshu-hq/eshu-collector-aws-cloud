// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"strings"
	"testing"
)

func dynamoResponses() map[string]string {
	return map[string]string{
		"DynamoDB_20120810.ListTables":    `{"TableNames":["t1"]}`,
		"DynamoDB_20120810.DescribeTable": `{"Table":{"TableArn":"arn:aws:dynamodb:us-east-1:1:table/t1","TableName":"t1"}}`,
	}
}

func TestListDynamoDBReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	cfg := stubServer(t, jsonStub(t, dynamoResponses(), nil))

	records, err := listDynamoDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listDynamoDB error = %v", err)
	}
	if len(records) != 1 || records[0].ID != "arn:aws:dynamodb:us-east-1:1:table/t1" || records[0].Name != "t1" {
		t.Fatalf("records = %v, want the stubbed table", records)
	}

	for _, tc := range []struct{ target, wrap string }{
		{"DynamoDB_20120810.ListTables", "dynamodb list tables"},
		{"DynamoDB_20120810.DescribeTable", "dynamodb describe table"},
	} {
		cfg := stubServer(t, jsonStub(t, dynamoResponses(), map[string]bool{tc.target: true}))
		if _, err := listDynamoDB(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.wrap) {
			t.Errorf("%s: error = %v, want %q", tc.target, err, tc.wrap)
		}
	}
}

func ecrResponses() map[string]string {
	return map[string]string{
		"AmazonEC2ContainerRegistry_V20150921.DescribeRepositories": `{"repositories":[{"repositoryArn":"arn:ecr:r1","repositoryName":"r1"}]}`,
		"AmazonEC2ContainerRegistry_V20150921.DescribeImages": `{"imageDetails":[` +
			`{"imageDigest":"sha256:1","imageTags":["v1"]},` +
			`{"imageDigest":"sha256:2","imageTags":[]}]}`,
	}
}

func TestListECRReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	cfg := stubServer(t, jsonStub(t, ecrResponses(), nil))

	records, err := listECR(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listECR error = %v", err)
	}
	// One repository plus two images: the tagged image takes its tag as the
	// name, the untagged image falls back to the digest.
	want := map[string]string{
		"arn:ecr:r1":          "r1",
		"arn:ecr:r1@sha256:1": "r1:v1",
		"arn:ecr:r1@sha256:2": "r1:sha256:2",
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
		{"AmazonEC2ContainerRegistry_V20150921.DescribeRepositories", "ecr describe repositories"},
		{"AmazonEC2ContainerRegistry_V20150921.DescribeImages", "ecr describe images"},
	} {
		cfg := stubServer(t, jsonStub(t, ecrResponses(), map[string]bool{tc.target: true}))
		if _, err := listECR(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.wrap) {
			t.Errorf("%s: error = %v, want %q", tc.target, err, tc.wrap)
		}
	}
}

func ecsResponses(serviceArns, taskArns []string) map[string]string {
	services := ""
	for i, arn := range serviceArns {
		if i > 0 {
			services += ","
		}
		services += `"` + arn + `"`
	}
	tasks := ""
	for i, arn := range taskArns {
		if i > 0 {
			tasks += ","
		}
		tasks += `"` + arn + `"`
	}
	return map[string]string{
		"AmazonEC2ContainerServiceV20141113.ListClusters":        `{"clusterArns":["arn:ecs:c1"]}`,
		"AmazonEC2ContainerServiceV20141113.DescribeClusters":    `{"clusters":[{"clusterArn":"arn:ecs:c1","clusterName":"c1"}]}`,
		"AmazonEC2ContainerServiceV20141113.ListServices":        `{"serviceArns":[` + services + `]}`,
		"AmazonEC2ContainerServiceV20141113.DescribeServices":    `{"services":[{"serviceArn":"arn:ecs:s","serviceName":"s"}]}`,
		"AmazonEC2ContainerServiceV20141113.ListTasks":           `{"taskArns":[` + tasks + `]}`,
		"AmazonEC2ContainerServiceV20141113.DescribeTasks":       `{"tasks":[{"taskArn":"arn:ecs:t/1"}]}`,
		"AmazonEC2ContainerServiceV20141113.ListTaskDefinitions": `{"taskDefinitionArns":["arn:ecs:td/1"]}`,
	}
}

func TestListECSReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	// The stub answers every Describe with one record, so two service chunks
	// and two task chunks prove the chunked Describe fan-out runs more than
	// once; chunks itself is unit-tested below for its batch boundaries.
	services := make([]string, 0, 11)
	for i := 0; i < 11; i++ {
		services = append(services, "arn:ecs:s")
	}
	tasks := make([]string, 0, 101)
	for i := 0; i < 101; i++ {
		tasks = append(tasks, "arn:ecs:t/1")
	}
	cfg := stubServer(t, jsonStub(t, ecsResponses(services, tasks), nil))

	records, err := listECS(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listECS error = %v", err)
	}
	// 1 cluster + 2 service chunks + 2 task chunks + 1 task definition.
	if len(records) != 6 {
		t.Fatalf("len(records) = %d, want 6", len(records))
	}
	if records[0].ID != "arn:ecs:c1" || records[0].Name != "c1" {
		t.Fatalf("records[0] = %+v, want the cluster", records[0])
	}
	if last := records[len(records)-1]; last.ID != "arn:ecs:td/1" || last.Name != "1" {
		t.Fatalf("records[last] = %+v, want the task definition", last)
	}

	single := []string{"arn:ecs:s"}
	oneTask := []string{"arn:ecs:t/1"}
	for _, tc := range []struct{ target, wrap string }{
		{"AmazonEC2ContainerServiceV20141113.ListClusters", "ecs list clusters"},
		{"AmazonEC2ContainerServiceV20141113.DescribeClusters", "ecs describe clusters"},
		{"AmazonEC2ContainerServiceV20141113.ListServices", "ecs list services"},
		{"AmazonEC2ContainerServiceV20141113.DescribeServices", "ecs describe services"},
		{"AmazonEC2ContainerServiceV20141113.ListTasks", "ecs list tasks"},
		{"AmazonEC2ContainerServiceV20141113.DescribeTasks", "ecs describe tasks"},
		{"AmazonEC2ContainerServiceV20141113.ListTaskDefinitions", "ecs list task definitions"},
	} {
		cfg := stubServer(t, jsonStub(t, ecsResponses(single, oneTask), map[string]bool{tc.target: true}))
		if _, err := listECS(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.wrap) {
			t.Errorf("%s: error = %v, want %q", tc.target, err, tc.wrap)
		}
	}
}

func TestListSQSReadsStubbedEndpoint(t *testing.T) {
	t.Parallel()

	responses := map[string]string{
		"AmazonSQS.ListQueues": `{"QueueUrls":["https://sqs.us-east-1.amazonaws.com/1/queue-1"]}`,
	}
	cfg := stubServer(t, jsonStub(t, responses, nil))

	records, err := listSQS(context.Background(), cfg)
	if err != nil {
		t.Fatalf("listSQS error = %v", err)
	}
	if len(records) != 1 || records[0].Name != "queue-1" {
		t.Fatalf("records = %v, want the stubbed queue", records)
	}

	cfg = stubServer(t, jsonStub(t, responses, map[string]bool{"AmazonSQS.ListQueues": true}))
	if _, err := listSQS(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "sqs list queues") {
		t.Fatalf("denied ListQueues: error = %v, want sqs list queues", err)
	}
}

// TestChunksBatchesDescribeInputs proves the Describe fan-out batches at
// exactly the call arity caps: a full batch plus remainder, an exact batch,
// and a short list.
func TestChunksBatchesDescribeInputs(t *testing.T) {
	t.Parallel()

	batched := chunks([]string{"a", "b", "c", "d", "e"}, 2)
	if len(batched) != 3 || len(batched[0]) != 2 || len(batched[2]) != 1 {
		t.Fatalf("chunks(5, 2) = %v, want [[a b] [c d] [e]]", batched)
	}
	if batched := chunks([]string{"a", "b"}, 2); len(batched) != 1 {
		t.Fatalf("chunks(2, 2) = %v, want one batch", batched)
	}
	if batched := chunks(nil, 10); len(batched) != 0 {
		t.Fatalf("chunks(nil, 10) = %v, want no batches", batched)
	}
}

// TestLastSegmentKeepsBareValues proves IDs without the separator pass
// through: the name fallback never mangles an already-bare identifier.
func TestLastSegmentKeepsBareValues(t *testing.T) {
	t.Parallel()

	if got := lastSegment("arn:lb/listener/l1", "/"); got != "l1" {
		t.Fatalf("lastSegment = %q, want l1", got)
	}
	if got := lastSegment("bare", "/"); got != "bare" {
		t.Fatalf("lastSegment = %q, want bare", got)
	}
	if got := lastSegment("trailing/", "/"); got != "trailing/" {
		t.Fatalf("lastSegment = %q, want trailing/", got)
	}
}
