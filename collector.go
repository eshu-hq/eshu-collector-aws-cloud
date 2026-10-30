// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

const (
	// ComponentID is this collector's manifest identity: the core-issued
	// producer ID from the in-tree AWS family declarations. It stays in
	// sync with manifest.yaml metadata.id and every grant producer_id.
	ComponentID = "collector-aws-cloud"
	// CollectorKind is the AWS collector family (scope.CollectorAWS).
	CollectorKind = "aws"
	// SourceSystem names the observed source: the AWS APIs this collector scans.
	SourceSystem = "aws"
	// MetricsPrefix is the component-owned metric prefix from the manifest.
	MetricsPrefix = "eshu_dp_aws_cloud_collector_"
)

const (
	// FactKindSnapshot summarizes one source report as source evidence.
	// TRANSITIONAL (PORT_PLAN.md): the placeholder pipeline still emits
	// this while the AWS logic port lands; the port removes it.
	FactKindSnapshot = "collector-aws-cloud.snapshot"
	// FactKindRecord records one source record as source evidence.
	// TRANSITIONAL (PORT_PLAN.md): removed by the AWS logic port.
	FactKindRecord = "collector-aws-cloud.record"
	// FactKindWarning records degraded-evidence warnings.
	// TRANSITIONAL (PORT_PLAN.md): removed by the AWS logic port.
	FactKindWarning = "collector-aws-cloud.warning"
)

// AWS fact kinds this collector emits or plans to emit at schema 1.0.0.
// They mirror the in-tree AWS family declarations
// (go/internal/facts/cloud): nine base kinds plus the EC2, S3, RDS posture
// and external-principal-grant families. Confidence is reported: the
// in-tree AWS envelopes record facts returned by the AWS APIs as
// facts.SourceConfidenceReported. Resource, relationship, and image reference
// are declared in Contract() and manifest.yaml; the other ten follow their
// typed emitter ports and trusted host grant context (#8909).
const (
	AWSKindResource                 = "aws_resource"
	AWSKindRelationship             = "aws_relationship"
	AWSKindTagObservation           = "aws_tag_observation"
	AWSKindDNSRecord                = "aws_dns_record"
	AWSKindImageReference           = "aws_image_reference"
	AWSKindSecurityGroupRule        = "aws_security_group_rule"
	AWSKindIAMPermission            = "aws_iam_permission"
	AWSKindResourcePolicyPermission = "aws_resource_policy_permission"
	AWSKindWarning                  = "aws_warning"
	AWSKindEC2InstancePosture       = "ec2_instance_posture"
	AWSKindS3BucketPosture          = "s3_bucket_posture"
	AWSKindRDSInstancePosture       = "rds_instance_posture"
	AWSKindS3ExternalPrincipalGrant = "s3_external_principal_grant"
)

// AWSKinds lists the core-owned AWS fact kinds for the logic port. Resource,
// relationship, and image reference are declared alongside transitional kinds.
var AWSKinds = []string{
	AWSKindResource,
	AWSKindRelationship,
	AWSKindTagObservation,
	AWSKindDNSRecord,
	AWSKindImageReference,
	AWSKindSecurityGroupRule,
	AWSKindIAMPermission,
	AWSKindResourcePolicyPermission,
	AWSKindWarning,
	AWSKindEC2InstancePosture,
	AWSKindS3BucketPosture,
	AWSKindRDSInstancePosture,
	AWSKindS3ExternalPrincipalGrant,
}

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

// Contract returns the Wave 0 emission contract: typed AWS resource,
// relationship, image-reference, warning, and specialty kinds (DNS record,
// security-group rule, IAM and resource-policy permissions, EC2/RDS/S3
// posture, S3 external-principal grant) alongside transitional families still
// emitted by the scaffold. The host must authorize each core-owned kind with
// a live grant; synthetic fixture context does not authorize production.
func Contract() sdk.Contract {
	return sdk.Contract{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Facts: append([]sdk.FactDeclaration{
			{
				Kind:             FactKindSnapshot,
				SchemaVersions:   []string{"1.0.0"},
				SourceConfidence: []sdk.SourceConfidence{sdk.SourceConfidenceReported},
			},
			{
				Kind:             FactKindRecord,
				SchemaVersions:   []string{"1.0.0"},
				SourceConfidence: []sdk.SourceConfidence{sdk.SourceConfidenceObserved},
			},
			{
				Kind:             FactKindWarning,
				SchemaVersions:   []string{"1.0.0"},
				SourceConfidence: []sdk.SourceConfidence{sdk.SourceConfidenceReported},
			},
			{
				Kind:             AWSKindResource,
				SchemaVersions:   []string{"1.0.0"},
				SourceConfidence: []sdk.SourceConfidence{sdk.SourceConfidenceReported},
			},
			{
				Kind:             AWSKindRelationship,
				SchemaVersions:   []string{"1.0.0"},
				SourceConfidence: []sdk.SourceConfidence{sdk.SourceConfidenceReported},
			},
			{
				Kind:             AWSKindImageReference,
				SchemaVersions:   []string{"1.0.0"},
				SourceConfidence: []sdk.SourceConfidence{sdk.SourceConfidenceReported},
			},
			{
				Kind:             AWSKindWarning,
				SchemaVersions:   []string{"1.0.0"},
				SourceConfidence: []sdk.SourceConfidence{sdk.SourceConfidenceReported},
			},
		}, append([]sdk.FactDeclaration{s3BucketPostureDeclaration()}, specialtyContractDeclarations()...)...),
	}
}

// maxReportBytes caps one source document. Reads past the cap fail instead
// of decoding unbounded input; emission bounds below still gate every fact.
const maxReportBytes = 32 << 20

// LoadReport decodes one placeholder source document.
func LoadReport(r io.Reader) (Report, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxReportBytes+1))
	if err != nil {
		return Report{}, fmt.Errorf("read report: %w", err)
	}
	if len(raw) > maxReportBytes {
		return Report{}, fmt.Errorf("source document exceeds %d bytes", maxReportBytes)
	}
	var report Report
	if err := json.Unmarshal(raw, &report); err != nil {
		return Report{}, fmt.Errorf("decode report: %w", err)
	}
	return report, nil
}

// Digest returns the stable identity of one report for freshness/stale proof.
// It covers every field that changes emitted facts: the source (snapshot
// payload), each record's emitted fields, and each record's redaction
// presence, so a stale digest never preserves stale evidence.
func Digest(report Report) string {
	ids := make([]string, 0, len(report.Records)+1)
	ids = append(ids, "source\x00"+report.Source)
	for _, record := range report.Records {
		secretPresence := "secret:0"
		if record.Secret != "" {
			secretPresence = "secret:1"
		}
		ids = append(ids, record.ID+"\x00"+record.Name+"\x00"+record.Detail+"\x00"+secretPresence)
	}
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, "\x01")))
	return hex.EncodeToString(sum[:])
}

// Collect builds one SDK result for the claimed scope and generation.
// Behavior contract, covered by conformance_test.go:
//   - empty input emits an authoritative complete snapshot with zero records
//     (retires stale evidence; distinct from unchanged freshness);
//   - unchanged digest emits ResultUnchanged (stale/freshness proof);
//   - duplicate record IDs emit one fact (idempotent re-emission);
//   - secrets never enter payloads; each redaction is recorded;
//   - source_ref carries claim scope, generation, and a credential-free URI;
//   - record, payload, and deadline bounds fail terminal, never unbounded.
func Collect(claim sdk.Claim, report Report, opts CollectOptions) (sdk.Result, error) {
	observedAt := opts.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	// Default per field, not wholesale: a partially customized Limits
	// keeps the caller's values (nestedLimits in cmd/collector already
	// defaults this way, so both entry points agree).
	limits := opts.Limits
	defaults := DefaultResourceUse()
	if limits.MaxRecordsPerClaim <= 0 {
		limits.MaxRecordsPerClaim = defaults.MaxRecordsPerClaim
	}
	if limits.MaxPayloadBytes <= 0 {
		limits.MaxPayloadBytes = defaults.MaxPayloadBytes
	}
	if limits.ClaimTimeoutSeconds <= 0 {
		limits.ClaimTimeoutSeconds = defaults.ClaimTimeoutSeconds
	}
	if !claim.Deadline.IsZero() && observedAt.After(claim.Deadline) {
		return terminalResult(claim, observedAt, "claim-deadline-exceeded"), nil
	}
	if err := sdk.ValidateShareSafeKeys(map[string]any{"source": report.Source}); err != nil {
		return sdk.Result{}, err
	}
	if strings.TrimSpace(opts.SourceURI) == "" {
		return sdk.Result{}, fmt.Errorf("source URI must not be blank")
	}
	if err := checkSourceURI(opts.SourceURI); err != nil {
		return sdk.Result{}, err
	}
	if len(report.Records) > limits.MaxRecordsPerClaim {
		return terminalResult(claim, observedAt, "record-budget-exceeded"), nil
	}
	// PreviousDigest accepts the last emitted snapshot stable key (the
	// LastDigest the Monitor reports) or the raw report digest; either
	// match means the source has not moved since the last emission.
	digest := Digest(report)
	if opts.PreviousDigest != "" && len(report.Records) > 0 &&
		(opts.PreviousDigest == digest || opts.PreviousDigest == "snapshot:"+digest) {
		return sdk.Result{
			ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
			State:           sdk.ResultUnchanged,
			Claim:           claim,
			Generation:      sdk.Generation{ID: claim.GenerationID, ObservedAt: observedAt, FreshnessHint: "unchanged-digest"},
			Statuses:        []sdk.Status{{Class: sdk.StatusComplete, FactCount: 0}},
		}, nil
	}

	seen := map[string]bool{}
	facts := make([]sdk.Fact, 0, len(report.Records)+1)
	for _, record := range report.Records {
		key := "record:" + record.ID
		if seen[key] {
			continue
		}
		seen[key] = true
		payload := map[string]any{
			"id":   record.ID,
			"name": record.Name,
		}
		if record.Detail != "" {
			payload["detail"] = record.Detail
		}
		factRedactions := []sdk.Redaction{}
		if record.Secret != "" {
			factRedactions = append(factRedactions, sdk.Redaction{Field: "secret", Reason: "credential-redacted"})
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return sdk.Result{}, fmt.Errorf("encode record payload: %w", err)
		}
		if len(encoded) > limits.MaxPayloadBytes {
			return terminalResult(claim, observedAt, "payload-budget-exceeded"), nil
		}
		facts = append(facts, sdk.Fact{
			Kind:             FactKindRecord,
			SchemaVersion:    "1.0.0",
			StableKey:        key,
			SourceConfidence: sdk.SourceConfidenceObserved,
			ObservedAt:       observedAt,
			SourceRef: sdk.SourceRef{
				SourceSystem: SourceSystem,
				ScopeID:      claim.Scope.ID,
				GenerationID: claim.GenerationID,
				FactKey:      key,
				URI:          opts.SourceURI + "#" + record.ID,
				RecordID:     record.ID,
			},
			Payload:    payload,
			Redactions: factRedactions,
		})
	}
	snapshotPayload := map[string]any{"source": report.Source, "record_count": len(seen)}
	if encoded, err := json.Marshal(snapshotPayload); err != nil || len(encoded) > limits.MaxPayloadBytes {
		return terminalResult(claim, observedAt, "payload-budget-exceeded"), nil
	}
	snapshotKey := "snapshot:" + Digest(report)
	facts = append(facts, sdk.Fact{
		Kind:             FactKindSnapshot,
		SchemaVersion:    "1.0.0",
		StableKey:        snapshotKey,
		SourceConfidence: sdk.SourceConfidenceReported,
		ObservedAt:       observedAt,
		SourceRef: sdk.SourceRef{
			SourceSystem: SourceSystem,
			ScopeID:      claim.Scope.ID,
			GenerationID: claim.GenerationID,
			FactKey:      snapshotKey,
			URI:          opts.SourceURI,
			RecordID:     "snapshot",
		},
		Payload: snapshotPayload,
	})
	return sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultComplete,
		Claim:           claim,
		Generation:      sdk.Generation{ID: claim.GenerationID, ObservedAt: observedAt},
		Facts:           facts,
		Statuses:        []sdk.Status{{Class: sdk.StatusComplete, FactCount: len(facts)}},
	}, nil
}

// CollectPartial is the partial-failure shape: reachable records commit as
// ResultPartial with a warning status, never as an ambiguous complete.
func CollectPartial(claim sdk.Claim, report Report, opts CollectOptions, failure string) (sdk.Result, error) {
	result, err := Collect(claim, report, opts)
	if err != nil {
		return sdk.Result{}, err
	}
	if result.State != sdk.ResultComplete {
		return result, nil
	}
	// The cause travels as a FactKindWarning fact so operators see why the
	// claim is partial. The reason is share-safe validated first; an
	// unshareable cause is withheld and the redaction recorded instead.
	reason := strings.TrimSpace(failure)
	if reason == "" {
		reason = "source-degraded"
	}
	warningPayload := map[string]any{"reason": reason}
	warningRedactions := []sdk.Redaction{}
	// ValidateShareSafeKeys guards key shape; the reason travels as a value,
	// so credential-marker text is scanned separately. Either trip withholds
	// the cause and records the redaction instead of leaking it.
	if err := sdk.ValidateShareSafeKeys(map[string]any{"reason": reason}); err != nil || ContainsCredentialText(reason) {
		warningPayload = map[string]any{"reason": "withheld-unshareable-cause"}
		warningRedactions = append(warningRedactions, sdk.Redaction{Field: "reason", Reason: "unshareable-cause-redacted"})
	}
	observedAt := result.Generation.ObservedAt
	warningKey := "warning:partial:" + claim.GenerationID
	result.Facts = append(result.Facts, sdk.Fact{
		Kind:             FactKindWarning,
		SchemaVersion:    "1.0.0",
		StableKey:        warningKey,
		SourceConfidence: sdk.SourceConfidenceReported,
		ObservedAt:       observedAt,
		SourceRef: sdk.SourceRef{
			SourceSystem: SourceSystem,
			ScopeID:      claim.Scope.ID,
			GenerationID: claim.GenerationID,
			FactKey:      warningKey,
			URI:          opts.SourceURI + "#partial",
			RecordID:     "partial",
		},
		Payload:    warningPayload,
		Redactions: warningRedactions,
	})
	result.State = sdk.ResultPartial
	result.Statuses = append(result.Statuses, sdk.Status{Class: sdk.StatusWarning, Partial: true, WarningCount: 1, FactCount: len(result.Facts)})
	return result, nil
}

// terminalResult is the bounded-failure shape for exhausted budgets and
// expired claims: explicit terminal state with a failure class, never an
// ambiguous complete and never unbounded allocation.
func terminalResult(claim sdk.Claim, observedAt time.Time, failureClass string) sdk.Result {
	return sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultTerminal,
		Claim:           claim,
		Generation:      sdk.Generation{ID: claim.GenerationID, ObservedAt: observedAt},
		Statuses: []sdk.Status{{
			Class: sdk.StatusFailure, FailureClass: failureClass,
		}},
	}
}

// CollectRetryable is the bounded-retry shape for transient source errors.
func CollectRetryable(claim sdk.Claim, observedAt time.Time, retryAfterSeconds int) sdk.Result {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	return sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultRetryable,
		Claim:           claim,
		Generation:      sdk.Generation{ID: claim.GenerationID, ObservedAt: observedAt.UTC()},
		Statuses: []sdk.Status{{
			Class: sdk.StatusFailure, FailureClass: "transient", RetryAfterSeconds: retryAfterSeconds,
		}},
	}
}
