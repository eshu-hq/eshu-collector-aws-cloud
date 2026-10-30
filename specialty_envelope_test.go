// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"testing"
	"time"
)

// boundaryForParity builds the claim boundary for shared-fixture parity
// observations: the in-tree parity boundary pins account, region, fencing
// token 7, and the October 2026 observed-at instant, so only the service kind
// and the fixture scope triple vary per kind.
func boundaryForParity(t *testing.T, scopeID, generationID, instanceID, serviceKind string) Boundary {
	t.Helper()
	return Boundary{
		AccountID: "123456789012", Region: "us-east-1", ServiceKind: serviceKind,
		ScopeID: scopeID, GenerationID: generationID,
		CollectorInstanceID: instanceID, FencingToken: 7,
		ObservedAt: time.Date(2026, 10, 20, 13, 0, 0, 0, time.UTC),
	}
}
