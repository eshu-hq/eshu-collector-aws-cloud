// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
)

// TestWave1RDSBuilderConformance is the Wave 1 RDS Q4(a) gate over real
// reader output: every posture fact the production RDS readers emit for
// SDK-shaped describe rows (one DB instance, one DB cluster; the subnet
// group row carries resource identity only) validates against its checked-in
// JSON Schema through the SDK validator and the conformance harness. The
// root TestWave1RDSConformance guards only hand-built vectors; this test
// guards the builder-derived shapes that gate cannot see, and pins the
// reader-derived stable keys (Q4(b)): the same describe row yields the same
// key on repeat emission, instance and cluster keys differ, and the key
// inputs (account, region, resource id, resource type) survive the reader
// untouched, so the satellite key agrees with the in-tree scanner on shared
// input.
func TestWave1RDSBuilderConformance(t *testing.T) {
	t.Parallel()

	const accountID = "123456789012"
	instance := rdstypes.DBInstance{
		DBInstanceArn:         aws.String("arn:aws:rds:us-east-1:123456789012:db:wave1-db"),
		DBInstanceIdentifier:  aws.String("wave1-db"),
		DbiResourceId:         aws.String("db-WAVE1INSTANCE"),
		DBInstanceStatus:      aws.String("available"),
		Engine:                aws.String("postgres"),
		StorageEncrypted:      aws.Bool(true),
		MultiAZ:               aws.Bool(true),
		BackupRetentionPeriod: aws.Int32(7),
		DBParameterGroups: []rdstypes.DBParameterGroupStatus{
			{DBParameterGroupName: aws.String("wave1-params")},
		},
	}
	cluster := rdstypes.DBCluster{
		DBClusterArn:        aws.String("arn:aws:rds:us-east-1:123456789012:cluster:wave1-cluster"),
		DBClusterIdentifier: aws.String("wave1-cluster"),
		DbClusterResourceId: aws.String("cluster-WAVE1CLUSTER"),
		Status:              aws.String("available"),
		Engine:              aws.String("aurora-postgresql"),
		DeletionProtection:  aws.Bool(true),
	}

	instanceRow := rdsInstanceRecord(instance, "us-east-1")
	clusterRow := rdsClusterRecord(cluster, "us-east-1")
	groupRow := rdsSubnetGroupRecord(rdstypes.DBSubnetGroup{
		DBSubnetGroupArn:  aws.String("arn:aws:rds:us-east-1:123456789012:subgrp:wave1-subnet"),
		DBSubnetGroupName: aws.String("wave1-subnet"),
		SubnetGroupStatus: aws.String("Complete"),
	}, "us-east-1")
	if instanceRow.RDSPosture == nil || clusterRow.RDSPosture == nil {
		t.Fatal("RDS instance and cluster rows must carry posture observations")
	}
	if groupRow.RDSPosture != nil || groupRow.Resource == nil {
		t.Fatalf("RDS subnet group row must carry resource identity only: %#v", groupRow)
	}
	// The reader presets the region/service boundary the live fan-out keeps;
	// CollectReport stamps only the verified account.
	for name, posture := range map[string]collector.RDSPostureObservation{
		"instance": *instanceRow.RDSPosture, "cluster": *clusterRow.RDSPosture,
	} {
		if posture.Boundary.Region != "us-east-1" || posture.Boundary.ServiceKind != "rds" {
			t.Fatalf("%s posture boundary = %#v, want region us-east-1 service rds", name, posture.Boundary)
		}
	}
	if got := instanceRow.RDSPosture.ResourceID; got != "arn:aws:rds:us-east-1:123456789012:db:wave1-db" {
		t.Fatalf("instance posture resource id = %q, want the reported ARN", got)
	}
	if got := instanceRow.RDSPosture.ResourceType; got != "aws_rds_db_instance" {
		t.Fatalf("instance posture resource type = %q, want aws_rds_db_instance", got)
	}
	if got := clusterRow.RDSPosture.ResourceType; got != "aws_rds_db_cluster" {
		t.Fatalf("cluster posture resource type = %q, want aws_rds_db_cluster", got)
	}

	observedAt := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	result := sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultComplete,
		Claim: sdk.Claim{
			ComponentID: collector.ComponentID, InstanceID: "aws-parity-wave1",
			CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem,
			Scope:       sdk.Scope{ID: "aws:123456789012:us-east-1", Kind: "component"},
			SourceRunID: "wave1-parity-run", GenerationID: "aws:123456789012:us-east-1:wave1:1",
			WorkItemID: "wave1-parity-work", FencingToken: "wave1-parity-token",
			Attempt: 1, Deadline: observedAt.Add(time.Hour), ConfigHandle: "component-config:aws-cloud",
		},
		Generation: sdk.Generation{ID: "aws:123456789012:us-east-1:wave1:1", ObservedAt: observedAt},
	}

	keys := map[string]string{}
	for name, row := range map[string]collector.Record{"instance": instanceRow, "cluster": clusterRow} {
		posture := *row.RDSPosture
		posture.Boundary = wave1Boundary(accountID, "us-east-1", "rds")
		posture.SourceURI = "aws:rds:us-east-1:wave1-parity"
		first, err := collector.NewRDSInstancePostureFact(posture)
		if err != nil {
			t.Fatal(err)
		}
		second, err := collector.NewRDSInstancePostureFact(posture)
		if err != nil {
			t.Fatal(err)
		}
		if first.StableKey == "" || first.StableKey != second.StableKey {
			t.Fatalf("%s posture stable key is not deterministic: %q vs %q", name, first.StableKey, second.StableKey)
		}
		keys[name] = first.Kind + "\x00" + first.StableKey
		result.Facts = append(result.Facts, first)
	}
	if keys["instance"] == keys["cluster"] {
		t.Fatal("instance and cluster posture facts share a stable key")
	}
	if _, err := sdk.NewValidator(collector.Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected builder-derived wave1 RDS result: %v", err)
	}
	report := conformance.Run(wave1ConformanceRequest(t, []sdk.Result{result}))
	if !report.OK() {
		t.Fatalf("builder-derived wave1 RDS conformance findings = %#v, want passed", report.Findings)
	}
}
