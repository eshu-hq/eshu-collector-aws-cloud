// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"
)

func TestRDSPosturePreservesLegacyDescribeMetadata(t *testing.T) {
	instance := rdstypes.DBInstance{
		DBInstanceArn:        aws.String(" arn:aws:rds:us-east-1:123456789012:db:sample "),
		DBInstanceIdentifier: aws.String(" sample "), DbiResourceId: aws.String("db-resource-id"),
		DBInstanceStatus: aws.String("available"), Engine: aws.String("postgres"),
		PubliclyAccessible: aws.Bool(true), StorageEncrypted: aws.Bool(true),
		KmsKeyId:                         aws.String("arn:aws:kms:us-east-1:123456789012:key/k1"),
		IAMDatabaseAuthenticationEnabled: aws.Bool(true), MultiAZ: aws.Bool(true),
		DeletionProtection: aws.Bool(true), BackupRetentionPeriod: aws.Int32(7),
		PerformanceInsightsEnabled: aws.Bool(true), PerformanceInsightsRetentionPeriod: aws.Int32(14),
		PerformanceInsightsKMSKeyId: aws.String("arn:aws:kms:us-east-1:123456789012:key/pi"),
		CACertificateIdentifier:     aws.String("rds-ca-rsa2048-g1"),
		DBParameterGroups:           []rdstypes.DBParameterGroupStatus{{DBParameterGroupName: aws.String("secure-parameters")}},
		OptionGroupMemberships:      []rdstypes.OptionGroupMembership{{OptionGroupName: aws.String("secure-options")}},
		Endpoint:                    &rdstypes.Endpoint{Address: aws.String("internal-db.example")},
		MasterUsername:              aws.String("secret-user"), DBName: aws.String("private-database"),
	}
	row := rdsInstanceRecord(instance, "us-east-1")
	if row.Resource == nil || row.RDSPosture == nil {
		t.Fatalf("instance typed output missing: %#v", row)
	}
	if row.Resource.ResourceID != "arn:aws:rds:us-east-1:123456789012:db:sample" || row.Resource.ResourceType != "aws_rds_db_instance" || row.Resource.State != "available" {
		t.Fatalf("instance identity = %#v", row.Resource)
	}
	if len(row.Resource.CorrelationAnchors) != 4 || row.Resource.CorrelationAnchors[3] != "internal-db.example" {
		t.Fatalf("legacy anchors = %#v", row.Resource.CorrelationAnchors)
	}
	posture := row.RDSPosture
	if !posture.PubliclyAccessible || !posture.StorageEncrypted || !posture.IAMDatabaseAuthenticationEnabled || !posture.MultiAZ || !posture.DeletionProtection || posture.BackupRetentionPeriod != 7 || !posture.PerformanceInsightsEnabled || posture.PerformanceInsightsRetentionDays != 14 || posture.CACertificateIdentifier != "rds-ca-rsa2048-g1" || len(posture.ParameterGroups) != 1 || posture.ParameterGroups[0] != "secure-parameters" || len(posture.OptionGroups) != 1 || posture.OptionGroups[0] != "secure-options" {
		t.Fatalf("instance posture = %#v", posture)
	}
	posture.Boundary = collector.Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "rds", ScopeID: "scope", GenerationID: "generation", CollectorInstanceID: "collector", ClaimToken: "fence"}
	posture.SourceURI = "aws://123456789012"
	fact, err := collector.NewRDSPostureFact(*posture)
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != collector.AWSKindRDSInstancePosture || fact.SourceRef.RecordID != row.Resource.ResourceID || fact.Payload["publicly_accessible"] != true || fact.Payload["backup_retention_period"] != int32(7) || fact.Payload["ca_certificate_identifier"] != "rds-ca-rsa2048-g1" {
		t.Fatalf("instance posture fact = %#v", fact)
	}
	for key, want := range map[string]any{
		"account_id": "123456789012", "region": "us-east-1", "resource_type": "aws_rds_db_instance",
		"resource_id": row.Resource.ResourceID, "identifier": "sample", "engine": "postgres",
		"storage_encrypted": true, "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/k1",
		"iam_database_authentication_enabled": true, "multi_az": true, "deletion_protection": true,
		"performance_insights_enabled": true, "performance_insights_retention_days": int32(14),
		"performance_insights_kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/pi",
	} {
		if got := fact.Payload[key]; got != want {
			t.Fatalf("RDS payload %s = %#v, want %#v", key, got, want)
		}
	}
	if fact.SourceRef.ScopeID != "scope" || fact.SourceRef.GenerationID != "generation" || fact.SourceRef.FactKey != fact.StableKey || fact.SourceRef.URI != "aws://123456789012" {
		t.Fatalf("RDS posture provenance = %#v", fact.SourceRef)
	}
	encoded, err := json.Marshal(fact.Payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"internal-db.example", "secret-user", "private-database", "security_parameters", "endpoint_address", "master_username"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("posture leaked %q: %s", forbidden, encoded)
		}
	}
	cluster := rdstypes.DBCluster{
		DBClusterArn:        aws.String("arn:aws:rds:us-east-1:123456789012:cluster:sample"),
		DBClusterIdentifier: aws.String("sample"), DbClusterResourceId: aws.String("cluster-resource-id"),
		Status: aws.String("available"), Engine: aws.String("aurora-postgresql"),
		DBClusterParameterGroup: aws.String("secure-cluster-parameters"),
		Endpoint:                aws.String("writer.example"), ReaderEndpoint: aws.String("reader.example"),
		MasterUsername: aws.String("cluster-secret-user"), DatabaseName: aws.String("cluster-private-database"),
	}
	clusterRow := rdsClusterRecord(cluster, "us-east-1")
	if clusterRow.Resource == nil || clusterRow.RDSPosture == nil || clusterRow.Resource.ResourceType != "aws_rds_db_cluster" || clusterRow.RDSPosture.ResourceID != clusterRow.Resource.ResourceID || len(clusterRow.RDSPosture.ParameterGroups) != 1 || clusterRow.RDSPosture.ParameterGroups[0] != "secure-cluster-parameters" {
		t.Fatalf("cluster typed output = %#v", clusterRow)
	}
	if clusterRow.RDSPosture.PubliclyAccessible || clusterRow.RDSPosture.BackupRetentionPeriod != 0 || len(clusterRow.RDSPosture.OptionGroups) != 0 {
		t.Fatalf("missing cluster pointers did not follow legacy zero semantics: %#v", clusterRow.RDSPosture)
	}
	clusterPosture := *clusterRow.RDSPosture
	clusterPosture.Boundary = posture.Boundary
	clusterPosture.SourceURI = posture.SourceURI
	clusterFact, err := collector.NewRDSPostureFact(clusterPosture)
	if err != nil {
		t.Fatal(err)
	}
	schema, ok := fixturepack.SchemaFor("rds_instance_posture")
	if !ok {
		t.Fatal("pinned fixture pack lacks RDS posture schema")
	}
	if err := conformance.ValidatePayloadSchemas(map[string]json.RawMessage{collector.AWSKindRDSInstancePosture: schema}, sdk.Result{Facts: []sdk.Fact{fact, clusterFact}}); err != nil {
		t.Fatalf("emitted RDS posture payloads violate pinned schema: %v", err)
	}
	if clusterFact.StableKey == fact.StableKey || clusterFact.Payload["resource_type"] != "aws_rds_db_cluster" || clusterFact.Payload["parameter_groups"] == nil || clusterFact.Payload["backup_retention_period"] != int32(0) {
		t.Fatalf("cluster posture payload = %#v", clusterFact)
	}
	clusterEncoded, err := json.Marshal(clusterFact.Payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"writer.example", "reader.example", "cluster-secret-user", "cluster-private-database", "security_parameters"} {
		if strings.Contains(string(clusterEncoded), forbidden) {
			t.Fatalf("cluster posture leaked %q: %s", forbidden, clusterEncoded)
		}
	}
	group := rdsSubnetGroupRecord(rdstypes.DBSubnetGroup{DBSubnetGroupArn: aws.String("arn:aws:rds:us-east-1:123456789012:subgrp:sample"), DBSubnetGroupName: aws.String("sample"), SubnetGroupStatus: aws.String("Complete")}, "us-east-1")
	if group.Resource == nil || group.Resource.ResourceType != "aws_rds_db_subnet_group" || group.RDSPosture != nil {
		t.Fatalf("subnet group typed output = %#v", group)
	}
}

func TestRDSPostureClaimBoundCountsEveryFact(t *testing.T) {
	rows := []collector.Record{
		rdsInstanceRecord(rdstypes.DBInstance{DBInstanceArn: aws.String("arn:aws:rds:us-east-1:123456789012:db:sample"), DBInstanceIdentifier: aws.String("sample")}, "us-east-1"),
		rdsClusterRecord(rdstypes.DBCluster{DBClusterArn: aws.String("arn:aws:rds:us-east-1:123456789012:cluster:sample"), DBClusterIdentifier: aws.String("sample")}, "us-east-1"),
		rdsSubnetGroupRecord(rdstypes.DBSubnetGroup{DBSubnetGroupArn: aws.String("arn:aws:rds:us-east-1:123456789012:subgrp:sample"), DBSubnetGroupName: aws.String("sample")}, "us-east-1"),
	}
	outcome, err := (Collector{
		LoadConfig: func(_ context.Context, region string) (aws.Config, error) { return aws.Config{Region: region}, nil },
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{"rds": func(context.Context, aws.Config, VerifiedIdentity) ([]collector.Record, error) { return rows, nil }},
	}).CollectReport(context.Background(), Config{AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"rds"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Report.Records) != 3 || len(outcome.Resources) != 3 || len(outcome.RDSPostures) != 2 {
		t.Fatalf("RDS report = %#v", outcome)
	}
	claim := sdk.Claim{ComponentID: collector.ComponentID, InstanceID: "collector", CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem, Scope: sdk.Scope{ID: "scope", Kind: "component"}, GenerationID: "generation", FencingToken: "fence"}
	limits := collector.ResourceUse{MaxRecordsPerClaim: 9, MaxPayloadBytes: 65536}
	base, err := collector.Collect(claim, outcome.Report, collector.CollectOptions{SourceURI: "aws://123456789012", ObservedAt: time.Now().UTC(), Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := collector.AppendLiveResources(base, outcome.Resources, "aws://123456789012", limits)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := collector.AppendLiveRDSPostures(resources, outcome.RDSPostures, "aws://123456789012", limits)
	if err != nil || complete.State != sdk.ResultComplete || len(complete.Facts) != 9 || complete.Statuses[0].FactCount != 9 {
		t.Fatalf("nine-fact RDS result = %#v, err %v", complete, err)
	}
	limits.MaxRecordsPerClaim = 8
	limited, err := collector.AppendLiveRDSPostures(resources, outcome.RDSPostures, "aws://123456789012", limits)
	if err != nil || limited.State != sdk.ResultTerminal || len(limited.Facts) != 0 {
		t.Fatalf("eight-fact limit truncated RDS: %#v, err %v", limited, err)
	}
}
