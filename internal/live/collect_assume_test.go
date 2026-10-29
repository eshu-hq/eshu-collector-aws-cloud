// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

func verifiedAccount(account string) func(context.Context, aws.Config) (VerifiedIdentity, error) {
	return func(_ context.Context, _ aws.Config) (VerifiedIdentity, error) {
		return VerifiedIdentity{AccountID: account, Partition: "aws"}, nil
	}
}

// TestCollectReportAssumesScopeRole proves a scope carrying credentials is
// read with assumed-role credentials: the assumer exchanges the ambient
// config, the loaders run against the assumed config, and the observations
// carry the target account.
func TestCollectReportAssumesScopeRole(t *testing.T) {
	t.Parallel()

	const target = "111122223333"
	const role = "arn:aws:iam::111122223333:role/irsa-eshu-aws-collector-cross-account-role"
	var regions []string
	var assumed []string
	sawAssumed := false
	c := Collector{
		LoadConfig:     fakeConfig(&regions),
		VerifyIdentity: verifiedAccount(target),
		AssumeRole: func(_ context.Context, base aws.Config, roleARN, externalID string) (aws.Config, error) {
			assumed = append(assumed, roleARN+"/"+externalID)
			out := base
			out.Credentials = aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("ASSUMED", "x", "x"))
			return out, nil
		},
		Loaders: map[string]Loader{
			"ecs": func(ctx context.Context, cfg aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
				if creds, err := cfg.Credentials.Retrieve(ctx); err == nil && creds.AccessKeyID == "ASSUMED" {
					sawAssumed = true
				}
				return []collector.Record{{
					ID: "arn:cluster", Name: "cluster", Detail: "d",
					Resource: &collector.LiveResource{
						Region: "us-east-1", ServiceKind: "ecs",
						ResourceType: "aws_ecs_cluster", ResourceID: "cluster",
					},
				}}, nil
			},
		},
	}
	config := Config{
		AccountID: target, Regions: []string{"us-east-1"}, Services: []string{"ecs"},
		RoleARN: role, ExternalID: "eshu-ops-qa-collector",
	}
	outcome, err := c.CollectReport(context.Background(), config)
	if err != nil {
		t.Fatalf("CollectReport error = %v", err)
	}
	if len(assumed) != 1 || assumed[0] != role+"/eshu-ops-qa-collector" {
		t.Fatalf("assumed = %v, want one assume of the scope role", assumed)
	}
	if !sawAssumed {
		t.Fatal("ecs loader did not run against assumed credentials")
	}
	if len(outcome.Resources) != 1 || outcome.Resources[0].Boundary.AccountID != target {
		t.Fatalf("resources = %+v, want one observation bound to %s", outcome.Resources, target)
	}
}

// TestCollectReportFailsClosedOnAssumeError proves an assume-role failure is
// terminal: the claim errors instead of emitting an empty success that would
// retire the target account's evidence.
func TestCollectReportFailsClosedOnAssumeError(t *testing.T) {
	t.Parallel()

	boom := errors.New("sts denied")
	c := Collector{
		LoadConfig:     fakeConfig(&[]string{}),
		VerifyIdentity: verifiedAccount("111122223333"),
		AssumeRole: func(_ context.Context, _ aws.Config, _, _ string) (aws.Config, error) {
			return aws.Config{}, boom
		},
		Loaders: map[string]Loader{},
	}
	config := Config{
		AccountID: "111122223333", Regions: []string{"us-east-1"}, Services: []string{"ecs"},
		RoleARN:    "arn:aws:iam::111122223333:role/irsa-eshu-aws-collector-cross-account-role",
		ExternalID: "eshu-ops-qa-collector",
	}
	if _, err := c.CollectReport(context.Background(), config); !errors.Is(err, boom) {
		t.Fatalf("CollectReport error = %v, want the assume failure", err)
	}
}

// TestCollectReportFailsClosedWithoutAssumer proves a scope role with no
// assume-role implementation fails closed instead of silently reading with
// ambient credentials from the wrong account.
func TestCollectReportFailsClosedWithoutAssumer(t *testing.T) {
	t.Parallel()

	c := Collector{
		LoadConfig:     fakeConfig(&[]string{}),
		VerifyIdentity: verifiedAccount("111122223333"),
		Loaders:        map[string]Loader{},
	}
	config := Config{
		AccountID: "111122223333", Regions: []string{"us-east-1"}, Services: []string{"ecs"},
		RoleARN:    "arn:aws:iam::111122223333:role/irsa-eshu-aws-collector-cross-account-role",
		ExternalID: "eshu-ops-qa-collector",
	}
	if _, err := c.CollectReport(context.Background(), config); err == nil {
		t.Fatal("CollectReport error = nil, want fail-closed without an assumer")
	}
}

// TestCollectReportListsOnlyAllowlistedServices proves the orchestrator calls
// exactly the configured service-region pairs: nothing outside the host
