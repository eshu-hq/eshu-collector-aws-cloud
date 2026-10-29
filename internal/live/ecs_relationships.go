// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"strings"

	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
)

// ecsServiceTaskDefinitionRelationship carries the service's reported revision.
func ecsServiceTaskDefinitionRelationship(serviceARN, definitionARN, region string) (collector.LiveRelationship, bool) {
	serviceARN = strings.TrimSpace(serviceARN)
	definitionARN = strings.TrimSpace(definitionARN)
	if serviceARN == "" || definitionARN == "" {
		return collector.LiveRelationship{}, false
	}
	return collector.LiveRelationship{
		Region: region, ServiceKind: "ecs",
		RelationshipType: catalog.RelationshipECSServiceUsesTaskDefinition,
		SourceResourceID: serviceARN, SourceARN: serviceARN,
		TargetResourceID: definitionARN, TargetARN: definitionARN,
		TargetType:     catalog.ResourceTypeECSTaskDefinition,
		SourceRecordID: serviceARN + "#task-definition#" + definitionARN,
	}, true
}

// ecsTaskNetworkInterfaceRelationships carries ENI IDs reported on task attachments.
func ecsTaskNetworkInterfaceRelationships(taskARN, region string, interfaces []map[string]any, ids []string) []collector.LiveRelationship {
	if taskARN == "" {
		return nil
	}
	var edges []collector.LiveRelationship
	for i, id := range ids {
		edges = append(edges, collector.LiveRelationship{
			Region: region, ServiceKind: "ecs",
			RelationshipType: catalog.RelationshipECSTaskUsesNetworkInterface,
			SourceResourceID: taskARN, SourceARN: taskARN,
			TargetResourceID: id, TargetType: catalog.ResourceTypeEC2NetworkInterface,
			Attributes:     interfaces[i],
			SourceRecordID: taskARN + "#network-interface#" + id,
		})
	}
	return edges
}
