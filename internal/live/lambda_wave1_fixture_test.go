// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// wave1LambdaFixture mirrors the shared fixture rows in their in-tree
// post-mapper shape. The stub below serves the same rows as Lambda REST-JSON
// responses; the in-tree oracle unmarshals the same bytes directly into its
// scanner types.
type wave1LambdaFixture struct {
	ScopeID             string               `json:"scope_id"`
	GenerationID        string               `json:"generation_id"`
	CollectorInstanceID string               `json:"collector_instance_id"`
	Functions           []wave1LambdaRow     `json:"functions"`
	Aliases             []wave1LambdaAlias   `json:"aliases"`
	Mappings            []wave1LambdaMapping `json:"mappings"`
}

type wave1LambdaRow struct {
	ARN              string
	Name             string
	Runtime          string
	RoleARN          string
	Handler          string
	Description      string
	State            string
	LastUpdateStatus string
	PackageType      string
	Version          string
	CodeSHA256       string
	CodeSize         int64
	ImageURI         string
	ResolvedImageURI string
	KMSKeyARN        string
	SourceKMSKeyARN  string
	MemorySize       int32
	TimeoutSeconds   int32
	LastModified     time.Time
	Architectures    []string
	Environment      map[string]string
	VPCConfig        wave1LambdaVPCConfig
	LoggingConfig    wave1LambdaLoggingConfig
	Tags             map[string]string
}

type wave1LambdaVPCConfig struct {
	VPCID            string
	SubnetIDs        []string
	SecurityGroupIDs []string
	IPv6AllowedForDS bool
}

type wave1LambdaLoggingConfig struct {
	LogGroup            string
	LogFormat           string
	ApplicationLogLevel string
	SystemLogLevel      string
}

type wave1LambdaAlias struct {
	FunctionName    string
	ARN             string
	Name            string
	FunctionARN     string
	FunctionVersion string
	Description     string
	RevisionID      string
	RoutingWeights  map[string]float64
}

type wave1LambdaMapping struct {
	FunctionName          string
	ARN                   string
	UUID                  string
	FunctionARN           string
	EventSourceARN        string
	State                 string
	LastProcessingResult  string
	StartingPosition      string
	BatchSize             int32
	MaximumRetryAttempts  int32
	ParallelizationFactor int32
}

func loadWave1LambdaFixture(t *testing.T) wave1LambdaFixture {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/wave1-lambda-parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture wave1LambdaFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
