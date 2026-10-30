// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"

	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	"github.com/eshu-hq/eshu-sdk/factschema"
)

// frozenEC2InstancePostureKey is the in-tree stable key for the Wave 0
// fixture instance (testdata/wave0-specialty-parity.json, ec2_posture
// section), executed through the in-tree NewEC2InstancePostureEnvelope.
// Re-derivation recipe (oracle commit, builder, fixture hash):
// testdata/stable-key-provenance.md.
const frozenEC2InstancePostureKey = "1d55bc572f6f73fa02e8c9ae08da14dec300825d4a8c52dbbcfe8bc894a86786"

func ec2PostureParityObservation(t *testing.T) EC2InstancePostureObservation {
	t.Helper()
	in := loadWave0Fixture(t).EC2Posture
	devices := make([]EC2BlockDevicePosture, 0, len(in.BlockDevices))
	for _, device := range in.BlockDevices {
		devices = append(devices, EC2BlockDevicePosture{
			DeviceName:          device.DeviceName,
			VolumeID:            device.VolumeID,
			DeleteOnTermination: device.DeleteOnTermination,
			Status:              device.Status,
		})
	}
	return EC2InstancePostureObservation{
		Boundary:                wave0Boundary(t, catalog.ServiceEC2),
		ARN:                     in.ARN,
		InstanceID:              in.InstanceID,
		State:                   in.State,
		IMDSv2Required:          in.IMDSv2Required,
		HTTPEndpoint:            in.HTTPEndpoint,
		HTTPPutResponseHopLimit: in.HTTPPutResponseHopLimit,
		UserDataPresent:         in.UserDataPresent,
		DetailedMonitoring:      in.DetailedMonitoring,
		EBSOptimized:            in.EBSOptimized,
		PublicIPAssociated:      in.PublicIPAssociated,
		InstanceProfileARN:      in.InstanceProfileARN,
		Tenancy:                 in.Tenancy,
		NitroEnclaveEnabled:     in.NitroEnclaveEnabled,
		BlockDevices:            devices,
		SourceURI:               "aws:ec2:instance/i-parity1234567890ab",
		SourceRecordID:          "ec2-posture-row-1",
	}
}

func TestEC2InstancePostureFactWave0Parity(t *testing.T) {
	t.Parallel()

	fact, err := NewEC2InstancePostureFact(ec2PostureParityObservation(t))
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindEC2InstancePosture || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.StableKey != frozenEC2InstancePostureKey {
		t.Fatalf("StableKey = %q, want in-tree frozen %q", fact.StableKey, frozenEC2InstancePostureKey)
	}
	decoded, err := factschema.DecodeEC2InstancePosture(factschema.Envelope{
		FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload,
	})
	if err != nil || decoded.InstanceID == nil || *decoded.InstanceID != "i-parity1234567890ab" {
		t.Fatalf("typed decode = %+v, %v", decoded, err)
	}
}

func TestEC2InstancePostureFactRejectsHostileInput(t *testing.T) {
	t.Parallel()

	observation := ec2PostureParityObservation(t)
	observation.ARN = ""
	observation.InstanceID = "   "
	if _, err := NewEC2InstancePostureFact(observation); err == nil {
		t.Fatal("blank instance identity accepted")
	}
}
