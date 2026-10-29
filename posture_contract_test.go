// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import "testing"

func TestEC2InstancePostureDeclaredForEmission(t *testing.T) {
	declared := false
	for _, fact := range Contract().Facts {
		if fact.Kind == AWSKindEC2InstancePosture {
			declared = true
			if len(fact.SchemaVersions) != 1 || fact.SchemaVersions[0] != "1.0.0" {
				t.Fatalf("posture schema versions = %#v", fact.SchemaVersions)
			}
		}
	}
	if !declared {
		t.Fatal("EC2 instance posture is not declared")
	}
	manifest := loadManifest(t)
	for _, fact := range manifest.Spec.EmittedFacts {
		if fact.Kind == AWSKindEC2InstancePosture {
			return
		}
	}
	t.Fatal("EC2 instance posture is absent from manifest")
}
