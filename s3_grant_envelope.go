// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"strings"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/factschema"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

const (
	// S3ExternalPrincipalKindPublic identifies the wildcard public principal.
	S3ExternalPrincipalKindPublic = "public"
	// S3ExternalPrincipalKindAWSAccount identifies a bare AWS account principal.
	S3ExternalPrincipalKindAWSAccount = "aws_account"
	// S3ExternalPrincipalKindAWSARN identifies an AWS principal ARN.
	S3ExternalPrincipalKindAWSARN = "aws_arn"
	// S3ExternalPrincipalKindAWSService identifies an AWS service principal.
	S3ExternalPrincipalKindAWSService = "aws_service"
	// S3ExternalPrincipalKindUnsupported identifies a principal type that was
	// present but intentionally not persisted as exact graph-ready identity.
	S3ExternalPrincipalKindUnsupported = "unsupported"

	// S3ExternalPrincipalGrantOutcomePublic marks a wildcard public grant.
	S3ExternalPrincipalGrantOutcomePublic = "public"
	// S3ExternalPrincipalGrantOutcomeCrossAccount marks an exact AWS principal in
	// an account other than the bucket owner.
	S3ExternalPrincipalGrantOutcomeCrossAccount = "cross_account"
	// S3ExternalPrincipalGrantOutcomeAWSService marks an AWS service principal.
	S3ExternalPrincipalGrantOutcomeAWSService = "aws_service"
	// S3ExternalPrincipalGrantOutcomeUnsupported marks a principal shape that was
	// detected but not exact enough for graph projection.
	S3ExternalPrincipalGrantOutcomeUnsupported = "unsupported_principal"
)

// S3ExternalPrincipalGrantObservation describes one bounded S3 bucket-policy
// grant to an external principal. It carries only principal identity metadata
// and derived outcome flags. The raw policy document, statement body, actions,
// resources, conditions, ACL grants, object keys, and object data must not
// reach this observation. Field-for-field it mirrors the in-tree observation
// so a shared fixture feeds both builders.
type S3ExternalPrincipalGrantObservation struct {
	Boundary Boundary

	BucketARN  string
	BucketName string

	PrincipalKind      string
	PrincipalValue     string
	PrincipalAccountID string
	PrincipalPartition string
	PrincipalService   string
	GrantOutcome       string

	Public           bool
	CrossAccount     bool
	ServicePrincipal bool
	Unsupported      bool
	UnsupportedKey   string

	SourceStatementID string
	SourceURI         string
	SourceRecordID    string
}

// NewS3ExternalPrincipalGrantFact builds a durable
// s3_external_principal_grant fact for one metadata-only bucket-policy
// principal observation. It validates that both bucket and principal
// identities are present and emits no graph truth. Derivation mirrors the
// in-tree NewS3ExternalPrincipalGrantEnvelope verbatim so stable keys agree
// on shared input.
func NewS3ExternalPrincipalGrantFact(observation S3ExternalPrincipalGrantObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(observation.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	bucketARN := strings.TrimSpace(observation.BucketARN)
	bucketName := strings.TrimSpace(observation.BucketName)
	if bucketARN == "" && bucketName == "" {
		return sdk.Fact{}, fmt.Errorf("s3 external principal grant observation requires bucket_arn or bucket_name")
	}
	bucketIdentity := bucketARN
	if bucketIdentity == "" {
		bucketIdentity = bucketName
	}
	principalKind := strings.TrimSpace(observation.PrincipalKind)
	principalValue := strings.TrimSpace(observation.PrincipalValue)
	if principalKind == "" || principalValue == "" {
		return sdk.Fact{}, fmt.Errorf("s3 external principal grant observation requires principal_kind and principal_value")
	}
	grantOutcome := strings.TrimSpace(observation.GrantOutcome)
	if grantOutcome == "" {
		return sdk.Fact{}, fmt.Errorf("s3 external principal grant observation requires grant_outcome")
	}

	stableKey, err := specialtyStableKey(AWSKindS3ExternalPrincipalGrant, map[string]any{
		"account_id":      observation.Boundary.AccountID,
		"bucket":          bucketIdentity,
		"grant_outcome":   grantOutcome,
		"principal_kind":  principalKind,
		"principal_value": principalValue,
		"region":          observation.Boundary.Region,
	})
	if err != nil {
		return sdk.Fact{}, err
	}
	anchors := specialtyAnchors(nil, bucketARN, bucketName, s3GrantURI(bucketName), principalValue)
	payload, err := factschema.EncodeS3ExternalPrincipalGrant(awsv1.S3ExternalPrincipalGrant{
		AccountID:           observation.Boundary.AccountID,
		Region:              observation.Boundary.Region,
		ServiceKind:         specialtyBoundaryValue(observation.Boundary.ServiceKind),
		CollectorInstanceID: specialtyBoundaryValue(observation.Boundary.CollectorInstanceID),
		BucketARN:           specialtyStringPtr(bucketARN),
		BucketName:          specialtyStringPtr(bucketName),
		PrincipalKind:       principalKind,
		PrincipalValue:      principalValue,
		PrincipalAccountID:  specialtyStringPtr(strings.TrimSpace(observation.PrincipalAccountID)),
		PrincipalPartition:  specialtyStringPtr(strings.TrimSpace(observation.PrincipalPartition)),
		PrincipalService:    specialtyStringPtr(strings.TrimSpace(observation.PrincipalService)),
		GrantOutcome:        grantOutcome,
		IsPublic:            observation.Public || principalKind == S3ExternalPrincipalKindPublic || grantOutcome == S3ExternalPrincipalGrantOutcomePublic,
		IsCrossAccount:      observation.CrossAccount || grantOutcome == S3ExternalPrincipalGrantOutcomeCrossAccount,
		IsServicePrincipal:  observation.ServicePrincipal || principalKind == S3ExternalPrincipalKindAWSService || grantOutcome == S3ExternalPrincipalGrantOutcomeAWSService,
		IsUnsupported:       observation.Unsupported || principalKind == S3ExternalPrincipalKindUnsupported || grantOutcome == S3ExternalPrincipalGrantOutcomeUnsupported,
		UnsupportedKey:      specialtyStringPtr(strings.TrimSpace(observation.UnsupportedKey)),
		SourceStatementID:   specialtyStringPtr(strings.TrimSpace(observation.SourceStatementID)),
		CorrelationAnchors:  anchors,
	})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode s3_external_principal_grant payload: %w", err)
	}
	recordID := strings.TrimSpace(observation.SourceRecordID)
	if recordID == "" {
		recordID = bucketIdentity + "#grant#" + principalKind + "#" + principalValue
	}
	return specialtyFact(AWSKindS3ExternalPrincipalGrant, stableKey, observation.Boundary, observation.SourceURI, recordID, payload)
}

// s3GrantURI returns the s3:// correlation URI for a bucket name, or empty
// when the name is blank.
func s3GrantURI(bucketName string) string {
	bucketName = strings.TrimSpace(bucketName)
	if bucketName == "" {
		return ""
	}
	return "s3://" + bucketName
}
