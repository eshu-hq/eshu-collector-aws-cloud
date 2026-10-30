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

// NewRDSInstancePostureFact builds the durable rds_instance_posture fact for
// one RDS DB instance or Aurora DB cluster. The fact captures derived
// security and operations posture (public exposure, encryption and KMS key,
// IAM database authentication, backup/multi-AZ/deletion-protection,
// Performance Insights configuration, parameter/option-group identity, a
// curated set of security-relevant non-default parameters, and the CA
// certificate identifier) as metadata-only control-plane evidence. It never
// carries database contents, master usernames, connection secrets, snapshot
// payloads, log bodies, or Performance Insights samples. It emits no graph
// edges and mirrors the in-tree NewRDSInstancePostureEnvelope verbatim so
// stable keys agree on shared input.
func NewRDSInstancePostureFact(observation RDSPostureObservation) (sdk.Fact, error) {
	if err := validateResourceBoundary(observation.Boundary); err != nil {
		return sdk.Fact{}, err
	}
	arn := strings.TrimSpace(observation.ARN)
	resourceID := strings.TrimSpace(observation.ResourceID)
	if arn == "" && resourceID == "" {
		return sdk.Fact{}, fmt.Errorf("rds posture observation requires arn or resource_id")
	}
	if resourceID == "" {
		resourceID = arn
	}
	resourceType := strings.TrimSpace(observation.ResourceType)
	if resourceType == "" {
		return sdk.Fact{}, fmt.Errorf("rds posture observation requires resource_type")
	}
	identifier := strings.TrimSpace(observation.Identifier)
	stableKey, err := specialtyStableKey(AWSKindRDSInstancePosture, map[string]any{
		"account_id":    observation.Boundary.AccountID,
		"region":        observation.Boundary.Region,
		"resource_id":   resourceID,
		"resource_type": resourceType,
	})
	if err != nil {
		return sdk.Fact{}, err
	}
	anchors := specialtyAnchors(nil, arn, resourceID, identifier)
	securityParameters := cloneRDSSecurityParameters(observation.SecurityParameters)
	var securityParametersPtr *map[string]string
	if securityParameters != nil {
		securityParametersPtr = &securityParameters
	}
	payload, err := factschema.EncodeRDSInstancePosture(awsv1.RDSInstancePosture{
		AccountID:                        observation.Boundary.AccountID,
		Region:                           observation.Boundary.Region,
		ServiceKind:                      specialtyBoundaryValue(observation.Boundary.ServiceKind),
		CollectorInstanceID:              specialtyBoundaryValue(observation.Boundary.CollectorInstanceID),
		ARN:                              specialtyStringPtr(arn),
		ResourceID:                       specialtyStringPtr(resourceID),
		ResourceType:                     specialtyStringPtr(resourceType),
		Identifier:                       specialtyStringPtr(identifier),
		Engine:                           specialtyStringPtr(strings.TrimSpace(observation.Engine)),
		PubliclyAccessible:               observation.PubliclyAccessible,
		StorageEncrypted:                 observation.StorageEncrypted,
		KMSKeyID:                         specialtyStringPtr(strings.TrimSpace(observation.KMSKeyID)),
		IAMDatabaseAuthenticationEnabled: observation.IAMDatabaseAuthenticationEnabled,
		MultiAZ:                          observation.MultiAZ,
		DeletionProtection:               observation.DeletionProtection,
		BackupRetentionPeriod:            observation.BackupRetentionPeriod,
		PerformanceInsightsEnabled:       observation.PerformanceInsightsEnabled,
		PerformanceInsightsRetentionDays: observation.PerformanceInsightsRetentionDays,
		PerformanceInsightsKMSKeyID:      specialtyStringPtr(strings.TrimSpace(observation.PerformanceInsightsKMSKeyID)),
		CACertificateIdentifier:          specialtyStringPtr(strings.TrimSpace(observation.CACertificateIdentifier)),
		ParameterGroups:                  cloneRDSStrings(observation.ParameterGroups),
		OptionGroups:                     cloneRDSStrings(observation.OptionGroups),
		SecurityParameters:               securityParametersPtr,
		CorrelationAnchors:               anchors,
	})
	if err != nil {
		return sdk.Fact{}, fmt.Errorf("encode rds_instance_posture payload: %w", err)
	}
	recordID := strings.TrimSpace(observation.SourceRecordID)
	if recordID == "" {
		recordID = resourceType + ":" + resourceID
	}
	return specialtyFact(AWSKindRDSInstancePosture, stableKey, observation.Boundary, observation.SourceURI, recordID, payload)
}

func cloneRDSSecurityParameters(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func cloneRDSStrings(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	output := make([]string, len(input))
	copy(output, input)
	return output
}
