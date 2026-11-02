// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// AppendOutcomeFacts appends every typed observation family in one
// Outcome to result, in the single order production relies on. Both
// cmd/collector/collectLivePlan and the pipeline parity test call this
// function, so deleting or reordering an appender here fails the test
// instead of silently dropping a fact family in production.
//
// It also reports the typed-evidence digest: a stable hash over exactly
// the typed facts appended here, never the transitional placeholder
// facts. Freshness and health key off this digest, so deleting or
// reordering an appender changes it and fails the digest test instead of
// silently shifting what freshness compares.
func AppendOutcomeFacts(result sdk.Result, outcome Outcome, sourceURI string, limits collector.ResourceUse) (sdk.Result, string, error) {
	var err error
	if result, err = collector.AppendLiveResources(result, outcome.Resources, sourceURI, limits); err != nil {
		return result, "", err
	}
	if result, err = collector.AppendLiveRelationships(result, outcome.Relationships, sourceURI, limits); err != nil {
		return result, "", err
	}
	if result, err = collector.AppendLiveImageReferences(result, outcome.ImageReferences, sourceURI, limits); err != nil {
		return result, "", err
	}
	if result, err = collector.AppendLiveS3BucketPostures(result, outcome.S3Postures, sourceURI, limits); err != nil {
		return result, "", err
	}
	if result, err = collector.AppendLiveS3ExternalPrincipalGrants(result, outcome.S3Grants, sourceURI, limits); err != nil {
		return result, "", err
	}
	if result, err = collector.AppendLiveResourcePolicyPermissions(result, outcome.ResourcePolicyPermissions, sourceURI, limits); err != nil {
		return result, "", err
	}
	if result, err = collector.AppendLiveIAMPermissions(result, outcome.IAMPermissions, sourceURI, limits); err != nil {
		return result, "", err
	}
	if result, err = collector.AppendLiveSecurityGroupRulePostures(result, outcome.SGPostures, sourceURI, limits); err != nil {
		return result, "", err
	}
	if result, err = collector.AppendLiveEC2InstancePostures(result, outcome.EC2Postures, sourceURI, limits); err != nil {
		return result, "", err
	}
	if result, err = collector.AppendLiveRDSPostures(result, outcome.RDSPostures, sourceURI, limits); err != nil {
		return result, "", err
	}
	if result, err = collector.AppendLiveDNSRecords(result, outcome.DNSRecords, sourceURI, limits); err != nil {
		return result, "", err
	}
	if result, err = collector.AppendLiveWarnings(result, outcome.WarningObservations, sourceURI, limits); err != nil {
		return result, "", err
	}
	return result, typedEvidenceDigest(result), nil
}

// typedEvidenceDigest hashes the stable keys of exactly the typed facts
// in result, in sorted order. Transitional placeholder kinds
// (snapshot/record/warning) never contribute: their keys churn with the
// placeholder report shape, which freshness must not track. Empty typed
// evidence yields the empty digest, which never matches a previous
// digest and therefore never short-circuits to unchanged.
func typedEvidenceDigest(result sdk.Result) string {
	ids := make([]string, 0, len(result.Facts))
	for _, fact := range result.Facts {
		switch fact.Kind {
		case collector.FactKindSnapshot, collector.FactKindRecord, collector.FactKindWarning:
			continue
		}
		if fact.StableKey == "" {
			continue
		}
		ids = append(ids, fact.Kind+"\x00"+fact.StableKey)
	}
	if len(ids) == 0 {
		return ""
	}
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, "\x01")))
	return hex.EncodeToString(sum[:])
}
