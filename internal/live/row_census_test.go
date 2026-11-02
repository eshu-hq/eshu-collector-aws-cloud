// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"reflect"
	"testing"
)

// Row-home census for drive 8852 (eshu-hq/eshu#8852). Every (service, kind)
// pair the satellite collectors can list must have a typed home (a prove
// func below), a legacy parity citation, or a pinned waiver. PR-D (deletion
// of the transitional snapshot/record kinds) is gated on this census having
// zero unwaived gaps. This file is a manually-maintained pinned inventory
// (verified 52/52 at this head): lister diffs must extend it by process.
// The gate pins the inventory against silent shrinkage or drift; it does
// not enumerate call sites.

// censusProved maps a listed row to the test proving its typed home through
// the production builder. Non-nil prove is compile-enforced: referencing a
// missing test breaks the build.
var censusProved = []struct {
	service string
	kind    string
	prove   func(*testing.T)
}{
	{"elbv2", "load-balancer", func(t *testing.T) { TestHomeElbv2LoadBalancer(t) }},
	{"elbv2", "listener", func(t *testing.T) { TestHomeElbv2Listener(t) }},
	{"elbv2", "rule", func(t *testing.T) { TestHomeElbv2Rule(t) }},
	{"elbv2", "target-group", func(t *testing.T) { TestHomeElbv2TargetGroup(t) }},
	{"apigateway", "rest-api", func(t *testing.T) { TestHomeApigatewayRestAPI(t) }},
	{"apigateway", "http-api", func(t *testing.T) { TestHomeApigatewayHTTPAPI(t) }},
	{"apigateway", "domain-name", func(t *testing.T) { TestHomeApigatewayDomainName(t) }},
	{"sqs", "queue", func(t *testing.T) { TestHomeSQSQueue(t) }},
	{"cloudwatchlogs", "log-group", func(t *testing.T) { TestHomeCloudWatchLogsLogGroup(t) }},
	{"eventbridge", "event-bus", func(t *testing.T) { TestHomeEventBridgeEventBus(t) }},
	{"eventbridge", "rule", func(t *testing.T) { TestHomeEventBridgeRule(t) }},
	{"iam", "policy", func(t *testing.T) { TestHomeIAMPolicy(t) }},
	{"iam", "instance-profile", func(t *testing.T) { TestHomeIAMInstanceProfile(t) }},
	{"iam", "oidc-provider", func(t *testing.T) {
		TestHomeIAMOIDCProvider(t)
		TestListIAMOIDCProvidersEnrichRows(t)
		TestListIAMOIDCProvidersDenialKeepsBareRows(t)
	}},
	{"dynamodb", "table", func(t *testing.T) { TestHomeDynamoDBTable(t) }},
	{"secretsmanager", "secret", func(t *testing.T) { TestHomeSecretsManagerSecret(t) }},
	{"route53", "hosted-zone", func(t *testing.T) { TestHostedZoneObservationMapsSDKZone(t) }},
}

// censusWaived pins listed rows with intentionally no satellite typed home.
// This set is closed: adding a waiver needs a linked issue or peer-lane
// reference, and TestRowCensusWaiversClosed fails on any other change.
var censusWaived = map[string]string{
	"cloudfront/distribution": "peer lane origin/drive/8852-cloudfront-typed owns the home (verify-only; no takeover)",
	"sns/topic":               "peer lane origin/drive/8852-sns-endpoint-edges owns the home (verify-only; no takeover)",
	"sns/subscription":        "peer lane origin/drive/8852-sns-endpoint-edges owns the home (verify-only; no takeover)",
}

// censusLegacy cites the pre-existing parity test covering each older typed
// home. Names are documentation; the cited tests themselves guard the rows.
var censusLegacy = []struct {
	service  string
	kind     string
	covering string
}{
	{"ec2", "vpc", "TestVPCRecordRetainsLegacyObservation"},
	{"ec2", "subnet", "TestSubnetRecordRetainsLegacyObservation"},
	{"ec2", "security-group", "TestSecurityGroupRecordCarriesVPCEdge"},
	{"ec2", "security-group-rule", "TestSecurityGroupRuleRecordRetainsLegacyObservation"},
	{"ec2", "network-interface", "TestNetworkInterfaceRecordRetainsLegacyObservation"},
	{"ec2", "instance", "TestInstanceRecordRetainsLegacyIdentityObservation"},
	{"ec2", "ami", "TestAMIOnlyResourcePreservesPlaceholderCount"},
	{"ec2", "volume", "TestVolumeRecordRetainsReportedEBSMetadata"},
	{"eks", "cluster", "TestEKSClusterRecordPreservesDescribeObservation"},
	{"eks", "addon", "TestEKSNodegroupAddonRelationships"},
	{"eks", "nodegroup", "TestEKSNodegroupRecordPreservesDescribeObservation"},
	{"eks", "oidc-provider", "TestEKSOIDCNoMatchRetainsIssuerResource"},
	{"kms", "key", "TestKMSKeyLoaderEmitsReportedIdentity"},
	{"kms", "alias", "TestWave1KMSLiveConformance"},
	{"kms", "grant", "TestWave1KMSLiveConformance"},
	{"lambda", "function", "TestLambdaFunctionRecordCarriesListFunctionsMetadata"},
	{"lambda", "alias", "TestLambdaAliasRecordPreservesReportedRouting"},
	{"lambda", "event-source-mapping", "TestWave1LambdaMappingAttributeEquality"},
	{"rds", "db-instance", "TestRDSPosturePreservesLegacyDescribeMetadata"},
	{"rds", "db-cluster", "TestRDSPosturePreservesLegacyDescribeMetadata"},
	{"rds", "db-subnet-group", "TestListRDSListsInstancesClustersSubnetGroups"},
	{"ecs", "cluster", "TestECSClusterRecordPreservesReportedObservation"},
	{"ecs", "service", "TestECSServiceRecordFailsMalformedLoadBalancer"},
	{"ecs", "task", "TestECSTaskRecordPreservesReportedObservation"},
	{"ecs", "task-definition", "TestECSTaskDefinitionRecordRequiresRedactionKey"},
	{"ssm", "parameter", "TestWave1SSMParameterRecordRejectsEmptyIdentity"},
	{"ecr", "repository", "TestECRRepositoryRecordRetainsLegacyObservation"},
	{"ecr", "image", "TestECRImageReferencesPreserveTagsAndDigest"},
	{"s3", "bucket", "TestS3BucketRecordBindsReportedIdentity"},
	{"iam", "role", "TestIAMRoleRecordUsesVerifiedIdentityAndSafeMetadata"},
	{"iam", "user", "TestIAMUserResourceGlobalAndNilPolicies"},
	{"route53", "record-set", "TestListRoute53AttachesDNSRecordObservations"},
}

// censusTotalPairs is the distinct (service, kind) inventory from the
// record() call-site census (drive 8852). Extend one of the three lists
// when a lister adds a row; the count pins the inventory.
const censusTotalPairs = 52

func TestRowCensusHomes(t *testing.T) {
	for _, row := range censusProved {
		t.Run(row.service+"/"+row.kind, row.prove)
	}
}

func TestRowCensusWaiversClosed(t *testing.T) {
	want := map[string]string{
		"cloudfront/distribution": "peer lane origin/drive/8852-cloudfront-typed owns the home (verify-only; no takeover)",
		"sns/topic":               "peer lane origin/drive/8852-sns-endpoint-edges owns the home (verify-only; no takeover)",
		"sns/subscription":        "peer lane origin/drive/8852-sns-endpoint-edges owns the home (verify-only; no takeover)",
	}
	if !reflect.DeepEqual(censusWaived, want) {
		t.Fatalf("waiver set changed = %#v, want %#v", censusWaived, want)
	}
}

func TestRowCensusComplete(t *testing.T) {
	seen := map[string]string{}
	for _, row := range censusProved {
		key := row.service + "/" + row.kind
		if prev, dup := seen[key]; dup {
			t.Fatalf("duplicate census pair %q (%s)", key, prev)
		}
		seen[key] = "proved"
	}
	for _, row := range censusLegacy {
		key := row.service + "/" + row.kind
		if prev, dup := seen[key]; dup {
			t.Fatalf("duplicate census pair %q (%s)", key, prev)
		}
		if row.covering == "" {
			t.Fatalf("legacy census pair %q has no covering test", key)
		}
		seen[key] = "legacy"
	}
	for key := range censusWaived {
		if prev, dup := seen[key]; dup {
			t.Fatalf("duplicate census pair %q (%s)", key, prev)
		}
		seen[key] = "waived"
	}
	if len(seen) != censusTotalPairs {
		t.Fatalf("census covers %d pairs, want %d: add the new row to proved, legacy, or waived", len(seen), censusTotalPairs)
	}
}
