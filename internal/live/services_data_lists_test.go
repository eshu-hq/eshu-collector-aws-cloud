// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// stubAWSConfig serves canned AWS responses without network access. The
// handler sees every request; unexpected operations must fail the test so a
// stub shape bug shows as a test failure, never as a silent empty page.
func stubAWSConfig(t *testing.T, handler http.Handler) aws.Config {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return aws.Config{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	}
}

func serveJSON(t *testing.T, body string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if _, err := w.Write([]byte(body)); err != nil {
			t.Errorf("write stub response: %v", err)
		}
	}
}

func TestListDynamoDBListsTables(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		switch {
		case strings.HasSuffix(target, "ListTables"):
			serveJSON(t, `{"TableNames": ["orders", "ghost"]}`)(w, r)
		case strings.HasSuffix(target, "DescribeTable"):
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "ghost") {
				serveJSON(t, `{}`)(w, r)
				return
			}
			serveJSON(t, `{"Table": {"TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/orders", "TableName": "orders"}}`)(w, r)
		default:
			t.Errorf("unexpected DynamoDB target %q", target)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	records, err := listDynamoDB(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1 (nil Table rows are skipped)", len(records))
	}
	if records[0].ID != "arn:aws:dynamodb:us-east-1:123456789012:table/orders" || records[0].Name != "orders" {
		t.Fatalf("table record = %#v", records[0])
	}
	if records[0].Detail != "service=dynamodb region=us-east-1 kind=table" {
		t.Fatalf("table detail = %q", records[0].Detail)
	}
}

func TestListDynamoDBDescribeError(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		if strings.HasSuffix(target, "ListTables") {
			serveJSON(t, `{"TableNames": ["orders"]}`)(w, r)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))

	if _, err := listDynamoDB(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "dynamodb describe table") {
		t.Fatalf("err = %v, want dynamodb describe table failure", err)
	}
}

func TestListSecretsManagerListsSecrets(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.Header.Get("X-Amz-Target"), "ListSecrets") {
			t.Errorf("unexpected SecretsManager target %q", r.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		serveJSON(t, `{"SecretList": [{"ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:api-key", "Name": "api-key"}]}`)(w, r)
	}))

	records, err := listSecretsManager(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1", len(records))
	}
	if records[0].ID != "arn:aws:secretsmanager:us-east-1:123456789012:secret:api-key" || records[0].Name != "api-key" {
		t.Fatalf("secret record = %#v", records[0])
	}
}

func TestListRDSListsInstancesClustersSubnetGroups(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		serve := func(body string) {
			w.Header().Set("Content-Type", "text/xml")
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write stub response: %v", err)
			}
		}
		switch r.Form.Get("Action") {
		case "DescribeDBInstances":
			serve(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance><DBInstanceIdentifier>orders-db</DBInstanceIdentifier><DBInstanceArn>arn:aws:rds:us-east-1:123456789012:db:orders-db</DBInstanceArn></DBInstance></DBInstances></DescribeDBInstancesResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></DescribeDBInstancesResponse>`)
		case "DescribeDBClusters":
			serve(`<DescribeDBClustersResponse><DescribeDBClustersResult><DBClusters><DBCluster><DBClusterIdentifier>orders-cluster</DBClusterIdentifier><DBClusterArn>arn:aws:rds:us-east-1:123456789012:cluster:orders-cluster</DBClusterArn></DBCluster></DBClusters></DescribeDBClustersResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></DescribeDBClustersResponse>`)
		case "DescribeDBSubnetGroups":
			serve(`<DescribeDBSubnetGroupsResponse><DescribeDBSubnetGroupsResult><DBSubnetGroups><DBSubnetGroup><DBSubnetGroupName>orders-subnets</DBSubnetGroupName><DBSubnetGroupArn>arn:aws:rds:us-east-1:123456789012:subgrp:orders-subnets</DBSubnetGroupArn></DBSubnetGroup></DBSubnetGroups></DescribeDBSubnetGroupsResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></DescribeDBSubnetGroupsResponse>`)
		default:
			t.Errorf("unexpected RDS action %q", r.Form.Get("Action"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	records, err := listRDS(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("record count = %d, want 3 (instance, cluster, subnet group)", len(records))
	}
	want := map[string]string{
		"arn:aws:rds:us-east-1:123456789012:db:orders-db":           "orders-db",
		"arn:aws:rds:us-east-1:123456789012:cluster:orders-cluster": "orders-cluster",
		"arn:aws:rds:us-east-1:123456789012:subgrp:orders-subnets":  "orders-subnets",
	}
	for _, record := range records {
		name, ok := want[record.ID]
		if !ok {
			t.Errorf("unexpected RDS record %#v", record)
			continue
		}
		if record.Name != name {
			t.Errorf("RDS record %q name = %q, want %q", record.ID, record.Name, name)
		}
		delete(want, record.ID)
	}
	for id := range want {
		t.Errorf("missing RDS record %q", id)
	}
}

func TestListSSMListsParameters(t *testing.T) {
	t.Parallel()

	cfg := stubAWSConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.Header.Get("X-Amz-Target"), "DescribeParameters") {
			t.Errorf("unexpected SSM target %q", r.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		serveJSON(t, `{"Parameters": [{"Name": "/app/config"}]}`)(w, r)
	}))

	records, err := listSSM(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1", len(records))
	}
	if records[0].Name != "/app/config" || records[0].Detail != "service=ssm region=us-east-1 kind=parameter" {
		t.Fatalf("parameter record = %#v", records[0])
	}
}
