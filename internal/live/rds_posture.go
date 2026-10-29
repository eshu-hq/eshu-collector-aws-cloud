// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// rdsInstanceRecord derives posture only from one already described DB instance.
func rdsInstanceRecord(raw rdstypes.DBInstance, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(raw.DBInstanceArn))
	identifier := strings.TrimSpace(aws.ToString(raw.DBInstanceIdentifier))
	id := rdsFirstNonEmpty(arn, aws.ToString(raw.DbiResourceId), identifier)
	row := record(arn, "rds", region, identifier, "db-instance")
	row.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "rds", ResourceType: "aws_rds_db_instance",
		ResourceID: id, ARN: arn, Name: identifier,
		State: strings.TrimSpace(aws.ToString(raw.DBInstanceStatus)), SourceRecordID: id,
		CorrelationAnchors: []string{arn, identifier, strings.TrimSpace(aws.ToString(raw.DbiResourceId)), rdsEndpointAddress(raw.Endpoint)},
	}
	row.RDSPosture = &collector.RDSPostureObservation{
		ARN: arn, ResourceID: id, ResourceType: "aws_rds_db_instance",
		Identifier: identifier, Engine: strings.TrimSpace(aws.ToString(raw.Engine)),
		PubliclyAccessible:               aws.ToBool(raw.PubliclyAccessible),
		StorageEncrypted:                 aws.ToBool(raw.StorageEncrypted),
		KMSKeyID:                         strings.TrimSpace(aws.ToString(raw.KmsKeyId)),
		IAMDatabaseAuthenticationEnabled: aws.ToBool(raw.IAMDatabaseAuthenticationEnabled),
		MultiAZ:                          aws.ToBool(raw.MultiAZ), DeletionProtection: aws.ToBool(raw.DeletionProtection),
		BackupRetentionPeriod:            aws.ToInt32(raw.BackupRetentionPeriod),
		PerformanceInsightsEnabled:       aws.ToBool(raw.PerformanceInsightsEnabled),
		PerformanceInsightsRetentionDays: aws.ToInt32(raw.PerformanceInsightsRetentionPeriod),
		PerformanceInsightsKMSKeyID:      strings.TrimSpace(aws.ToString(raw.PerformanceInsightsKMSKeyId)),
		CACertificateIdentifier:          strings.TrimSpace(aws.ToString(raw.CACertificateIdentifier)),
		ParameterGroups:                  rdsParameterGroupNames(raw.DBParameterGroups),
		OptionGroups:                     rdsOptionGroupNames(raw.OptionGroupMemberships),
		SourceRecordID:                   id,
	}
	return row
}

// rdsClusterRecord derives posture only from one already described DB cluster.
func rdsClusterRecord(raw rdstypes.DBCluster, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(raw.DBClusterArn))
	identifier := strings.TrimSpace(aws.ToString(raw.DBClusterIdentifier))
	id := rdsFirstNonEmpty(arn, aws.ToString(raw.DbClusterResourceId), identifier)
	row := record(arn, "rds", region, identifier, "db-cluster")
	row.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "rds", ResourceType: "aws_rds_db_cluster",
		ResourceID: id, ARN: arn, Name: identifier,
		State: strings.TrimSpace(aws.ToString(raw.Status)), SourceRecordID: id,
		CorrelationAnchors: []string{
			arn, identifier, strings.TrimSpace(aws.ToString(raw.DbClusterResourceId)),
			strings.TrimSpace(aws.ToString(raw.Endpoint)), strings.TrimSpace(aws.ToString(raw.ReaderEndpoint)),
		},
	}
	posture := &collector.RDSPostureObservation{
		ARN: arn, ResourceID: id, ResourceType: "aws_rds_db_cluster",
		Identifier: identifier, Engine: strings.TrimSpace(aws.ToString(raw.Engine)),
		PubliclyAccessible:               aws.ToBool(raw.PubliclyAccessible),
		StorageEncrypted:                 aws.ToBool(raw.StorageEncrypted),
		KMSKeyID:                         strings.TrimSpace(aws.ToString(raw.KmsKeyId)),
		IAMDatabaseAuthenticationEnabled: aws.ToBool(raw.IAMDatabaseAuthenticationEnabled),
		MultiAZ:                          aws.ToBool(raw.MultiAZ), DeletionProtection: aws.ToBool(raw.DeletionProtection),
		BackupRetentionPeriod:            aws.ToInt32(raw.BackupRetentionPeriod),
		PerformanceInsightsEnabled:       aws.ToBool(raw.PerformanceInsightsEnabled),
		PerformanceInsightsRetentionDays: aws.ToInt32(raw.PerformanceInsightsRetentionPeriod),
		PerformanceInsightsKMSKeyID:      strings.TrimSpace(aws.ToString(raw.PerformanceInsightsKMSKeyId)),
		SourceRecordID:                   id,
	}
	if group := strings.TrimSpace(aws.ToString(raw.DBClusterParameterGroup)); group != "" {
		posture.ParameterGroups = []string{group}
	}
	row.RDSPosture = posture
	return row
}

func rdsFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

// rdsSubnetGroupRecord retains the legacy identity and name anchors.
func rdsSubnetGroupRecord(raw rdstypes.DBSubnetGroup, region string) collector.Record {
	arn := strings.TrimSpace(aws.ToString(raw.DBSubnetGroupArn))
	name := strings.TrimSpace(aws.ToString(raw.DBSubnetGroupName))
	id := rdsFirstNonEmpty(arn, name)
	row := record(arn, "rds", region, name, "db-subnet-group")
	row.Resource = &collector.LiveResource{
		Region: region, ServiceKind: "rds", ResourceType: "aws_rds_db_subnet_group",
		ResourceID: id, ARN: arn, Name: name,
		State: strings.TrimSpace(aws.ToString(raw.SubnetGroupStatus)), SourceRecordID: id,
		CorrelationAnchors: []string{arn, name},
	}
	return row
}

func rdsEndpointAddress(endpoint *rdstypes.Endpoint) string {
	if endpoint == nil {
		return ""
	}
	return strings.TrimSpace(aws.ToString(endpoint.Address))
}

func rdsParameterGroupNames(groups []rdstypes.DBParameterGroupStatus) []string {
	var names []string
	for _, group := range groups {
		if name := strings.TrimSpace(aws.ToString(group.DBParameterGroupName)); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func rdsOptionGroupNames(groups []rdstypes.OptionGroupMembership) []string {
	var names []string
	for _, group := range groups {
		if name := strings.TrimSpace(aws.ToString(group.OptionGroupName)); name != "" {
			names = append(names, name)
		}
	}
	return names
}
