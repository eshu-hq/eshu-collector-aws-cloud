// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-collector-aws-cloud/catalog"
	"github.com/eshu-hq/eshu-sdk/factschema"
)

// frozenSecurityGroupRuleKey is the in-tree stable key for the Wave 0 fixture
// rule (testdata/wave0-specialty-parity.json, sg_rule section), executed
// through the in-tree NewSecurityGroupRuleEnvelope. Re-derivation recipe
// (oracle commit, builder, fixture hash):
// testdata/stable-key-provenance.md.
const frozenSecurityGroupRuleKey = "c4c4e0196ba9f6f2e22f4b67ee67affe0cb5b6839cfdeababa301cff33d80626"

type wave0Fixture struct {
	ScopeID             string `json:"scope_id"`
	GenerationID        string `json:"generation_id"`
	CollectorInstanceID string `json:"collector_instance_id"`
	SGRule              struct {
		RuleID       string `json:"rule_id"`
		GroupID      string `json:"group_id"`
		GroupOwnerID string `json:"group_owner_id"`
		IsEgress     bool   `json:"is_egress"`
		IPProtocol   string `json:"ip_protocol"`
		FromPort     *int32 `json:"from_port"`
		ToPort       *int32 `json:"to_port"`
		CIDRIPv4     string `json:"cidr_ipv4"`
		Description  string `json:"description"`
	} `json:"sg_rule"`
	ResourcePolicy struct {
		ResourceARN         string   `json:"resource_arn"`
		ResourceType        string   `json:"resource_type"`
		StatementSID        string   `json:"statement_sid"`
		Effect              string   `json:"effect"`
		Actions             []string `json:"actions"`
		Resources           []string `json:"resources"`
		ConditionKeys       []string `json:"condition_keys"`
		ConditionOperators  []string `json:"condition_operators"`
		PrincipalAccountIDs []string `json:"principal_account_ids"`
		PrincipalARNs       []string `json:"principal_arns"`
		PrincipalTypes      []string `json:"principal_types"`
		IsPublic            bool     `json:"is_public"`
		IsCrossAccount      bool     `json:"is_cross_account"`
	} `json:"resource_policy"`
	EC2Posture struct {
		ARN                     string `json:"arn"`
		InstanceID              string `json:"instance_id"`
		State                   string `json:"state"`
		IMDSv2Required          *bool  `json:"imdsv2_required"`
		HTTPEndpoint            string `json:"http_endpoint"`
		HTTPPutResponseHopLimit *int32 `json:"http_put_response_hop_limit"`
		UserDataPresent         *bool  `json:"user_data_present"`
		DetailedMonitoring      bool   `json:"detailed_monitoring"`
		EBSOptimized            bool   `json:"ebs_optimized"`
		PublicIPAssociated      bool   `json:"public_ip_associated"`
		InstanceProfileARN      string `json:"instance_profile_arn"`
		Tenancy                 string `json:"tenancy"`
		NitroEnclaveEnabled     bool   `json:"nitro_enclave_enabled"`
		BlockDevices            []struct {
			DeviceName          string `json:"device_name"`
			VolumeID            string `json:"volume_id"`
			DeleteOnTermination bool   `json:"delete_on_termination"`
			Status              string `json:"status"`
		} `json:"block_devices"`
	} `json:"ec2_posture"`
	RDSPosture struct {
		ARN                              string            `json:"arn"`
		ResourceID                       string            `json:"resource_id"`
		ResourceType                     string            `json:"resource_type"`
		Identifier                       string            `json:"identifier"`
		Engine                           string            `json:"engine"`
		PubliclyAccessible               bool              `json:"publicly_accessible"`
		StorageEncrypted                 bool              `json:"storage_encrypted"`
		KMSKeyID                         string            `json:"kms_key_id"`
		IAMDatabaseAuthenticationEnabled bool              `json:"iam_database_authentication_enabled"`
		MultiAZ                          bool              `json:"multi_az"`
		DeletionProtection               bool              `json:"deletion_protection"`
		BackupRetentionPeriod            int32             `json:"backup_retention_period"`
		PerformanceInsightsEnabled       bool              `json:"performance_insights_enabled"`
		PerformanceInsightsRetentionDays int32             `json:"performance_insights_retention_days"`
		CACertificateIdentifier          string            `json:"ca_certificate_identifier"`
		ParameterGroups                  []string          `json:"parameter_groups"`
		OptionGroups                     []string          `json:"option_groups"`
		SecurityParameters               map[string]string `json:"security_parameters"`
	} `json:"rds_posture"`
	S3Grant struct {
		BucketARN          string `json:"bucket_arn"`
		BucketName         string `json:"bucket_name"`
		PrincipalKind      string `json:"principal_kind"`
		PrincipalValue     string `json:"principal_value"`
		PrincipalAccountID string `json:"principal_account_id"`
		PrincipalPartition string `json:"principal_partition"`
		GrantOutcome       string `json:"grant_outcome"`
		Public             bool   `json:"public"`
		CrossAccount       bool   `json:"cross_account"`
		ServicePrincipal   bool   `json:"service_principal"`
		Unsupported        bool   `json:"unsupported"`
		SourceStatementID  string `json:"source_statement_id"`
	} `json:"s3_grant"`
}

func loadWave0Fixture(t *testing.T) wave0Fixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/wave0-specialty-parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture wave0Fixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func wave0Boundary(t *testing.T, serviceKind string) Boundary {
	t.Helper()
	fixture := loadWave0Fixture(t)
	return Boundary{
		AccountID: "123456789012", Region: "us-east-1", ServiceKind: serviceKind,
		ScopeID: fixture.ScopeID, GenerationID: fixture.GenerationID,
		CollectorInstanceID: fixture.CollectorInstanceID, FencingToken: 7,
		ObservedAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
	}
}

func sgRuleParityObservation(t *testing.T) SecurityGroupRuleObservation {
	t.Helper()
	in := loadWave0Fixture(t).SGRule
	return SecurityGroupRuleObservation{
		Boundary:       wave0Boundary(t, catalog.ServiceEC2),
		RuleID:         in.RuleID,
		GroupID:        in.GroupID,
		GroupOwnerID:   in.GroupOwnerID,
		IsEgress:       in.IsEgress,
		IPProtocol:     in.IPProtocol,
		FromPort:       in.FromPort,
		ToPort:         in.ToPort,
		CIDRIPv4:       in.CIDRIPv4,
		Description:    in.Description,
		SourceURI:      "aws:ec2:sg/sg-123",
		SourceRecordID: "sgr-row-1",
	}
}

func TestSecurityGroupRuleFactWave0Parity(t *testing.T) {
	t.Parallel()

	fact, err := NewSecurityGroupRuleFact(sgRuleParityObservation(t))
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindSecurityGroupRule || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.StableKey != frozenSecurityGroupRuleKey {
		t.Fatalf("StableKey = %q, want in-tree frozen %q", fact.StableKey, frozenSecurityGroupRuleKey)
	}
	if got, want := fact.Payload["direction"], "ingress"; got != want {
		t.Fatalf("direction = %#v, want %#v", got, want)
	}
	if got, want := fact.Payload["source_kind"], "cidr_ipv4"; got != want {
		t.Fatalf("source_kind = %#v, want %#v", got, want)
	}
	if got, want := fact.Payload["is_internet"], true; got != want {
		t.Fatalf("is_internet = %#v, want %#v", got, want)
	}
	decoded, err := factschema.DecodeAWSSecurityGroupRule(factschema.Envelope{
		FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload,
	})
	if err != nil || decoded.GroupID != "sg-123" {
		t.Fatalf("typed decode = %+v, %v", decoded, err)
	}
}

func TestSecurityGroupRuleFactRejectsHostileInput(t *testing.T) {
	t.Parallel()

	observation := sgRuleParityObservation(t)
	observation.GroupID = "  "
	if _, err := NewSecurityGroupRuleFact(observation); err == nil {
		t.Fatal("blank group_id accepted")
	}
	observation = sgRuleParityObservation(t)
	observation.Boundary.FencingToken = 0
	observation.Boundary.ClaimToken = ""
	if _, err := NewSecurityGroupRuleFact(observation); err == nil {
		t.Fatal("unfenced observation accepted")
	}
	observation = sgRuleParityObservation(t)
	observation.SourceURI = "aws:ec2:sg/sg-123?signature=opaque"
	if _, err := NewSecurityGroupRuleFact(observation); err == nil {
		t.Fatal("signed source URI accepted")
	}

	// An undescribed target preserves the rule as unknown-source evidence
	// instead of dropping it (in-tree unknown-source contract).
	observation = sgRuleParityObservation(t)
	observation.CIDRIPv4 = ""
	observation.RuleID = ""
	observation.SourceRecordID = ""
	fact, err := NewSecurityGroupRuleFact(observation)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fact.Payload["source_kind"], "unknown"; got != want {
		t.Fatalf("source_kind = %#v, want %#v", got, want)
	}
	if got, want := fact.SourceRef.RecordID, "sg-123#ingress#tcp#443#443#unknown#"; got != want {
		t.Fatalf("RecordID = %q, want %q", got, want)
	}

	// A nil port range (all-protocols rules omit it) renders as empty
	// segments, never as the Go "<nil>" token, in the durable id.
	observation = sgRuleParityObservation(t)
	observation.CIDRIPv4 = ""
	observation.RuleID = ""
	observation.SourceRecordID = ""
	observation.FromPort = nil
	observation.ToPort = nil
	fact, err = NewSecurityGroupRuleFact(observation)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fact.SourceRef.RecordID, "sg-123#ingress#tcp###unknown#"; got != want {
		t.Fatalf("RecordID = %q, want %q", got, want)
	}
	if strings.Contains(fact.SourceRef.RecordID, "<nil>") {
		t.Fatalf("RecordID = %q, contains Go <nil> token", fact.SourceRef.RecordID)
	}
}
