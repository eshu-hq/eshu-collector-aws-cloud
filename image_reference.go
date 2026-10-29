// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/factschema"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// NewImageReferenceFact builds the reported ECR image digest and tag fact.
func NewImageReferenceFact(observation ImageReferenceObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(observation.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	name, digest, tag := strings.TrimSpace(observation.RepositoryName), strings.TrimSpace(observation.ImageDigest), strings.TrimSpace(observation.Tag)
	if name == "" || digest == "" {
		return sdk.Fact{}, fmt.Errorf("aws image reference requires repository_name and image_digest")
	}
	uri := strings.TrimSpace(observation.SourceURI)
	if uri == "" {
		return sdk.Fact{}, fmt.Errorf("aws image reference requires source_uri")
	}
	if err := checkSourceURI(uri); err != nil {
		return sdk.Fact{}, err
	}
	manifestDigest := strings.TrimSpace(observation.ManifestDigest)
	if manifestDigest == "" {
		manifestDigest = digest
	}
	identity := map[string]any{
		"account_id": observation.Boundary.AccountID, "region": observation.Boundary.Region,
		"registry_id": strings.TrimSpace(observation.RegistryID), "repository_name": name,
		"image_digest": digest, "tag": tag,
	}
	wire, err := json.Marshal(map[string]any{"fact_type": AWSKindImageReference, "identity": identity})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode image reference identity: %w", err)
	}
	sum := sha256.Sum256(wire)
	key := hex.EncodeToString(sum[:])
	anchors := []string{digest, name + "@" + digest}
	if manifestDigest != digest {
		anchors = append([]string{digest, manifestDigest}, anchors[1:]...)
	}
	if tag != "" {
		anchors = append(anchors, name+":"+tag)
	}
	payload, err := factschema.EncodeAWSImageReference(awsv1.ImageReference{
		AccountID: observation.Boundary.AccountID, Region: observation.Boundary.Region,
		ServiceKind:         resourceStringPointer(strings.TrimSpace(observation.Boundary.ServiceKind)),
		CollectorInstanceID: resourceStringPointer(observation.Boundary.CollectorInstanceID),
		RepositoryARN:       resourceStringPointer(strings.TrimSpace(observation.RepositoryARN)),
		RepositoryName:      name, RegistryID: resourceStringPointer(strings.TrimSpace(observation.RegistryID)),
		ImageDigest: digest, ManifestDigest: manifestDigest, Tag: resourceStringPointer(tag),
		PushedAt: imageTimePointer(observation.PushedAt), ImageSizeInBytes: imageSizePointer(observation.ImageSizeInBytes),
		ManifestMediaType:  resourceStringPointer(strings.TrimSpace(observation.ManifestMediaType)),
		ArtifactMediaType:  resourceStringPointer(strings.TrimSpace(observation.ArtifactMediaType)),
		CorrelationAnchors: anchors,
	})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode image reference payload: %w", err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode image reference validation payload: %w", err)
	}
	var shared any
	if err := json.Unmarshal(encoded, &shared); err != nil {
		return sdk.Fact{}, fmt.Errorf("decode image reference validation payload: %w", err)
	}
	if err := sdk.ValidateShareSafeKeys(shared); err != nil {
		return sdk.Fact{}, fmt.Errorf("image reference payload contains unredacted sensitive key: %w", err)
	}
	observedAt := observation.Boundary.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	recordID := strings.TrimSpace(observation.SourceRecordID)
	if recordID == "" {
		recordID = name + "@" + digest + "#" + tag
	}
	return sdk.Fact{Kind: AWSKindImageReference, SchemaVersion: "1.0.0", StableKey: key,
		SourceConfidence: sdk.SourceConfidenceReported, ObservedAt: observedAt,
		SourceRef: sdk.SourceRef{SourceSystem: SourceSystem, ScopeID: observation.Boundary.ScopeID,
			GenerationID: observation.Boundary.GenerationID, FactKey: key, URI: uri, RecordID: recordID}, Payload: payload}, nil
}

func imageTimePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	utc := value.UTC()
	return &utc
}

func imageSizePointer(value int64) *int64 {
	if value == 0 {
		return nil
	}
	return &value
}
