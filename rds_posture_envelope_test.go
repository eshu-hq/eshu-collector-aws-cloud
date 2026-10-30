// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	"github.com/eshu-hq/eshu-sdk/factschema"
)

// frozenRDSInstancePostureKey is the in-tree stable key for the Wave 0
// fixture database (testdata/wave0-specialty-parity.json, rds_posture
// section), executed through the in-tree NewRDSInstancePostureEnvelope.
// Provenance for the frozen value is recorded on eshu-hq/eshu#9296 with the
// oracle run.
const frozenRDSInstancePostureKey = "99c0f021f1f7c26cd2598a915047ead7c55b72245cdee807b67f75d71c537d6d"

func rdsPostureParityObservation(t *testing.T) RDSPostureObservation {
	t.Helper()
	in := loadWave0Fixture(t).RDSPosture
	return RDSPostureObservation{
		Boundary:                         wave0Boundary(t, catalog.ServiceRDS),
		ARN:                              in.ARN,
		ResourceID:                       in.ResourceID,
		ResourceType:                     in.ResourceType,
		Identifier:                       in.Identifier,
		Engine:                           in.Engine,
		PubliclyAccessible:               in.PubliclyAccessible,
		StorageEncrypted:                 in.StorageEncrypted,
		KMSKeyID:                         in.KMSKeyID,
		IAMDatabaseAuthenticationEnabled: in.IAMDatabaseAuthenticationEnabled,
		MultiAZ:                          in.MultiAZ,
		DeletionProtection:               in.DeletionProtection,
		BackupRetentionPeriod:            in.BackupRetentionPeriod,
		PerformanceInsightsEnabled:       in.PerformanceInsightsEnabled,
		PerformanceInsightsRetentionDays: in.PerformanceInsightsRetentionDays,
		CACertificateIdentifier:          in.CACertificateIdentifier,
		ParameterGroups:                  in.ParameterGroups,
		OptionGroups:                     in.OptionGroups,
		SecurityParameters:               in.SecurityParameters,
		SourceURI:                        "aws:rds:db/parity-db",
		SourceRecordID:                   "rds-posture-row-1",
	}
}

func TestRDSInstancePostureFactWave0Parity(t *testing.T) {
	t.Parallel()

	fact, err := NewRDSInstancePostureFact(rdsPostureParityObservation(t))
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindRDSInstancePosture || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.StableKey != frozenRDSInstancePostureKey {
		t.Fatalf("StableKey = %q, want in-tree frozen %q", fact.StableKey, frozenRDSInstancePostureKey)
	}
	if got, want := fact.Payload["engine"], "postgres"; got != want {
		t.Fatalf("engine = %#v, want %#v", got, want)
	}
	decoded, err := factschema.DecodeRDSInstancePosture(factschema.Envelope{
		FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload,
	})
	if err != nil || decoded.ResourceID == nil || *decoded.ResourceID != "db-PARITY1234567890ABCDEF" {
		t.Fatalf("typed decode = %+v, %v", decoded, err)
	}
}

func TestRDSInstancePostureFactRejectsHostileInput(t *testing.T) {
	t.Parallel()

	observation := rdsPostureParityObservation(t)
	observation.ARN = ""
	observation.ResourceID = "  "
	if _, err := NewRDSInstancePostureFact(observation); err == nil {
		t.Fatal("blank RDS identity accepted")
	}
	observation = rdsPostureParityObservation(t)
	observation.ResourceType = ""
	if _, err := NewRDSInstancePostureFact(observation); err == nil {
		t.Fatal("blank resource_type accepted")
	}
}
