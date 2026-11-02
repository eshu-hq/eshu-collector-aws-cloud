// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
)

// TestWave1RDSConformance is the Wave 1 RDS Q4(a) gate over hand-built
// vectors: every kind the completed RDS live path emits validates against
// its checked-in JSON Schema through the public fixture harness, using only
// the published SDK modules. The observations below mirror the RDS describe
// rows (one DB instance, one DB cluster); the companion live test runs the
// real reader builders over SDK-shaped rows through the same harness
// (Q4(a)) and pins the reader-derived stable keys (Q4(b)). Hand-built
// vectors cannot exercise builder-derived edge shapes, so the live test
// guards the DB-instance and DB-cluster rows plus the posture-free subnet
// group row.
func TestWave1RDSConformance(t *testing.T) {
	t.Parallel()

	claim := testClaim()
	observedAt := testObservedAt()
	base := mustCollect(t, "complete.json", claim, observedAt, "")
	sourceURI := "aws://123456789012"

	resources := []ResourceObservation{
		{
			Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "rds"},
			ARN:          "arn:aws:rds:us-east-1:123456789012:db:wave1-db",
			ResourceID:   "arn:aws:rds:us-east-1:123456789012:db:wave1-db",
			ResourceType: "aws_rds_db_instance",
			Name:         "wave1-db",
			State:        "available",
			CorrelationAnchors: []string{
				"arn:aws:rds:us-east-1:123456789012:db:wave1-db", "wave1-db",
			},
			SourceRecordID: "arn:aws:rds:us-east-1:123456789012:db:wave1-db",
		},
		{
			Boundary:     Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "rds"},
			ARN:          "arn:aws:rds:us-east-1:123456789012:cluster:wave1-cluster",
			ResourceID:   "arn:aws:rds:us-east-1:123456789012:cluster:wave1-cluster",
			ResourceType: "aws_rds_db_cluster",
			Name:         "wave1-cluster",
			State:        "available",
			CorrelationAnchors: []string{
				"arn:aws:rds:us-east-1:123456789012:cluster:wave1-cluster", "wave1-cluster",
			},
			SourceRecordID: "arn:aws:rds:us-east-1:123456789012:cluster:wave1-cluster",
		},
	}
	rdsPostures := []RDSPostureObservation{
		{
			Boundary:              Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "rds"},
			ARN:                   "arn:aws:rds:us-east-1:123456789012:db:wave1-db",
			ResourceID:            "arn:aws:rds:us-east-1:123456789012:db:wave1-db",
			ResourceType:          "aws_rds_db_instance",
			Identifier:            "wave1-db",
			Engine:                "postgres",
			StorageEncrypted:      true,
			MultiAZ:               true,
			BackupRetentionPeriod: 7,
			SourceRecordID:        "arn:aws:rds:us-east-1:123456789012:db:wave1-db",
		},
		{
			Boundary:           Boundary{AccountID: "123456789012", Region: "us-east-1", ServiceKind: "rds"},
			ARN:                "arn:aws:rds:us-east-1:123456789012:cluster:wave1-cluster",
			ResourceID:         "arn:aws:rds:us-east-1:123456789012:cluster:wave1-cluster",
			ResourceType:       "aws_rds_db_cluster",
			Identifier:         "wave1-cluster",
			Engine:             "aurora-postgresql",
			StorageEncrypted:   true,
			DeletionProtection: true,
			SourceRecordID:     "arn:aws:rds:us-east-1:123456789012:cluster:wave1-cluster",
		},
	}

	result := base
	var err error
	result, err = AppendLiveResources(result, resources, sourceURI, ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	result, err = AppendLiveRDSPostures(result, rdsPostures, sourceURI, ResourceUse{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("SDK rejected wave1 RDS result: %v", err)
	}
	report := conformance.Run(coreFixtureRequest(t, harnessView(loadManifest(t)), []sdk.Result{result}))
	if !report.OK() {
		t.Fatalf("wave1 RDS conformance findings = %#v, want passed", report.Findings)
	}
}
