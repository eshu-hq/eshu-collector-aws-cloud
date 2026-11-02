// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"time"
)

// Report is the placeholder source document this template reads. Replace it
// with the real source artifact; keep the redaction-safe shape (no secrets in
// struct fields that land in payloads).
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Source      string    `json:"source"`
	Records     []Record  `json:"records"`
}

// Record is one live loader row or placeholder source row.
type Record struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Detail string `json:"detail,omitempty"`
	// Resource carries typed metadata from a live AWS read. The placeholder
	// report format does not accept it from a file.
	Resource *LiveResource `json:"-"`
	// S3Posture carries confirmed bucket settings and derived policy flags.
	S3Posture *S3BucketPostureObservation `json:"-"`
	// S3Grants carries one bounded external-principal grant per bucket-policy
	// Allow statement with a public, cross-account, service, or unsupported
	// principal. The live S3 reader sets it; Collect fans it out through
	// AppendLiveS3ExternalPrincipalGrants.
	S3Grants []S3ExternalPrincipalGrantObservation `json:"-"`
	// ResourcePolicyStatements carries one normalized metadata-only statement
	// per bucket-policy statement. The live S3 reader sets it; Collect fans
	// it out through AppendLiveResourcePolicyPermissions.
	ResourcePolicyStatements []ResourcePolicyPermissionObservation `json:"-"`
	// IAMPermissionStatements carries one normalized metadata-only statement
	// per IAM identity, trust, or permission-boundary policy statement. The
	// live IAM reader sets it; Collect fans it out through
	// AppendLiveIAMPermissions.
	IAMPermissionStatements []IAMPermissionObservation `json:"-"`
	// SGPosture carries one normalized security-group rule posture from a
	// DescribeSecurityGroupRules row. The live EC2 reader sets it; Collect
	// fans it out through AppendLiveSecurityGroupRulePostures.
	SGPosture *SecurityGroupRuleObservation `json:"-"`
	// EC2Posture carries one derived instance posture from a DescribeInstances
	// row. The live EC2 reader sets it; Collect fans it out through
	// AppendLiveEC2InstancePostures.
	EC2Posture *EC2InstancePostureObservation `json:"-"`
	// RDSPosture carries one derived instance or cluster posture from a
	// DescribeDBInstances or DescribeDBClusters row. The live RDS reader
	// sets it; Collect fans it out through AppendLiveRDSPostures.
	RDSPosture *RDSPostureObservation `json:"-"`
	// DNSRecord carries one normalized Route 53 record-set observation from
	// a ListResourceRecordSets row. The live Route 53 reader sets it for
	// supported rows only; Collect fans it out through AppendLiveDNSRecords.
	DNSRecord *DNSRecordObservation `json:"-"`
	// ImageReference carries a typed image digest and tag from DescribeImages.
	ImageReference *LiveImageReference `json:"-"`
	// Relationship carries one typed edge from a live AWS read.
	Relationship *LiveRelationship `json:"-"`
	// Relationships carries multiple typed edges from one live AWS read.
	Relationships []LiveRelationship `json:"-"`
	// TypedOnly keeps a synthetic typed target out of transitional record facts.
	TypedOnly bool `json:"-"`
	// Secret is intentionally never emitted: Collect redacts it and records
	// the redaction instead. Keep a field like this so the redaction path
	// stays exercised after the template is customized.
	Secret string `json:"secret,omitempty"`
}

// LiveResource is the source identity retained by a live AWS loader.
type LiveResource struct {
	Region       string
	ServiceKind  string
	ResourceType string
	ResourceID   string
	Name         string
	ARN          string
	State        string
	Tags         map[string]string
	Attributes   map[string]any
	// CorrelationAnchors carry source-reported join identities into the fact.
	CorrelationAnchors []string
	// SourceRecordID preserves a source-specific record key when it differs from the resource ID.
	SourceRecordID string
}

// LiveImageReference is one ECR image digest and tag reported by DescribeImages.
type LiveImageReference struct {
	Region, ServiceKind, RepositoryARN, RepositoryName, RegistryID string
	ImageDigest, ManifestDigest, Tag                               string
	PushedAt                                                       time.Time
	ImageSizeInBytes                                               int64
	ManifestMediaType, ArtifactMediaType                           string
}

// LiveRelationship is one relationship returned by a live AWS read.
type LiveRelationship struct {
	Region           string
	ServiceKind      string
	RelationshipType string
	SourceResourceID string
	SourceARN        string
	TargetResourceID string
	TargetARN        string
	TargetType       string
	SourceRecordID   string
	Attributes       map[string]any
}

// CollectOptions controls emission for one claimed scope.
type CollectOptions struct {
	ObservedAt     time.Time
	SourceURI      string
	PreviousDigest string
	// Limits bounds one claim's emission. Each non-positive field selects
	// its DefaultResourceUse value, so a partially customized Limits keeps
	// the caller's values and only the gaps fall back to defaults; the zero
	// value resolves to DefaultResourceUse, and an unconfigured copy still
	// fails terminal instead of allocating without bound.
	Limits ResourceUse
}
