// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func TestLambdaMappingDenialKeepsFunctionsAliasesAndOtherMappings(t *testing.T) {
	const firstARN = "arn:aws:lambda:us-east-1:123456789012:function:first"
	const secondARN = "arn:aws:lambda:us-east-1:123456789012:function:second"
	for _, code := range []string{"AccessDeniedException", "UnauthorizedOperation", "ThrottlingException"} {
		t.Run(code, func(t *testing.T) {
			calls := map[string]int{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				path := r.URL.Path
				calls[path]++
				switch {
				case path == "/2015-03-31/functions":
					fmt.Fprintf(w, `{"Functions":[{"FunctionName":"first","FunctionArn":%q},{"FunctionName":"second","FunctionArn":%q}]}`, firstARN, secondARN)
				case strings.HasPrefix(path, "/2015-03-31/functions/") && !strings.HasSuffix(path, "/aliases"):
					fmt.Fprintf(w, `{"Configuration":{"FunctionName":"first","FunctionArn":%q}}`, strings.TrimPrefix(path, "/2015-03-31/functions/"))
				case strings.HasSuffix(path, "/aliases"):
					fmt.Fprint(w, `{"Aliases":[{"Name":"live","AliasArn":"arn:aws:lambda:us-east-1:123456789012:function:first:live"}]}`)
				case path == "/2015-03-31/event-source-mappings" && r.URL.Query().Get("FunctionName") == firstARN:
					w.Header().Set("X-Amzn-Errortype", code)
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprintf(w, `{"Type":"%s","message":"denied"}`, code)
				case path == "/2015-03-31/event-source-mappings":
					fmt.Fprint(w, `{"EventSourceMappings":[{"UUID":"mapping-2","EventSourceArn":"arn:aws:sqs:us-east-1:123456789012:source"}]}`)
				default:
					t.Errorf("unexpected Lambda request: %s", r.URL)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			cfg := aws.Config{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(),
				Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
					return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
				}),
			}
			records, err := listLambda(context.Background(), cfg)
			if code == "ThrottlingException" {
				if err == nil || len(records) != 0 || calls["/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:second/aliases"] != 0 {
					t.Fatalf("required failure: records=%d err=%v calls=%v", len(records), err, calls)
				}
				return
			}
			denied, ok := err.(*optionalReadDenied)
			if !ok || len(denied.denials) != 1 {
				t.Fatalf("denial = %T %v", err, err)
			}
			if got := denied.denials[0]; got.operation != "ListEventSourceMappings" || got.resource != firstARN || got.effect == "" {
				t.Fatalf("denial identity = %+v", got)
			}
			if len(records) != 5 || calls["/2015-03-31/event-source-mappings"] != 2 {
				t.Fatalf("surviving records=%d, calls=%v", len(records), calls)
			}
			if code != "AccessDeniedException" {
				return
			}
			reader := Collector{
				LoadConfig: func(context.Context, string) (aws.Config, error) { return cfg, nil },
				VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
					return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
				},
				Loaders: map[string]Loader{"lambda": func(ctx context.Context, config aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
					return listLambda(ctx, config)
				}},
			}
			outcome, err := reader.CollectReport(context.Background(), Config{
				AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{"lambda"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(outcome.Warnings) != 1 || len(outcome.WarningObservations) != 1 || len(outcome.Resources) != 2 || len(outcome.Report.Records) != 5 {
				t.Fatalf("Lambda outcome: warnings=%v observations=%v resources=%d records=%d", outcome.Warnings, outcome.WarningObservations, len(outcome.Resources), len(outcome.Report.Records))
			}
			observedAt := time.Now().UTC()
			claim := sdk.Claim{ComponentID: collector.ComponentID, InstanceID: "aws-cloud-primary",
				CollectorKind: collector.CollectorKind, SourceSystem: collector.SourceSystem,
				Scope:       sdk.Scope{ID: "component:aws-cloud-primary", Kind: "component"},
				SourceRunID: "run-1", GenerationID: "generation-1", WorkItemID: "work-1", FencingToken: "fence-1",
				Attempt: 1, Deadline: observedAt.Add(time.Hour), ConfigHandle: "component-config:aws-cloud"}
			sourceURI := "aws://123456789012/us-east-1"
			limits := collector.DefaultResourceUse()
			result, err := collector.CollectPartial(claim, outcome.Report, collector.CollectOptions{
				ObservedAt: observedAt, SourceURI: sourceURI, Limits: limits,
			}, strings.Join(outcome.Warnings, "; "))
			if err != nil {
				t.Fatal(err)
			}
			result, err = collector.AppendLiveResources(result, outcome.Resources, sourceURI, limits)
			if err != nil {
				t.Fatal(err)
			}
			result, err = collector.AppendLiveWarnings(result, outcome.WarningObservations, sourceURI, limits)
			if err != nil {
				t.Fatal(err)
			}
			warnings := 0
			for _, fact := range result.Facts {
				if fact.Kind == collector.AWSKindWarning {
					warnings++
				}
			}
			if result.State != sdk.ResultPartial || warnings != 1 || len(result.Facts) < 6 {
				t.Fatalf("SDK partial state=%s warnings=%d facts=%d", result.State, warnings, len(result.Facts))
			}
		})
	}
}

func TestLambdaGetFunctionEnrichesSafeMetadataWithoutSecrets(t *testing.T) {
	const arn = "arn:aws:lambda:us-east-1:123456789012:function:worker"
	const image = "123456789012.dkr.ecr.us-east-1.amazonaws.com/team/worker:prod"
	const resolved = "123456789012.dkr.ecr.us-east-1.amazonaws.com/team/worker@sha256:abc123"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/2015-03-31/functions":
			fmt.Fprintf(w, `{"Functions":[{"FunctionName":"worker","FunctionArn":%q,"Runtime":"python3.12"}]}`, arn)
		case "/2015-03-31/functions/" + arn:
			fmt.Fprintf(w, `{"Configuration":{"FunctionName":"worker","FunctionArn":%q,"Runtime":"python3.13","Environment":{"Variables":{"API_KEY":"raw-secret"}}},"Code":{"ImageUri":%q,"ResolvedImageUri":%q,"SourceKMSKeyArn":"arn:aws:kms:us-east-1:123456789012:key/code","Location":"https://download.example/?token=raw-secret"},"Tags":{"team":"platform"}}`, arn, image, resolved)
		case "/2015-03-31/functions/" + arn + "/aliases":
			fmt.Fprint(w, `{}`)
		case "/2015-03-31/event-source-mappings":
			fmt.Fprint(w, `{}`)
		default:
			t.Errorf("unexpected Lambda request: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	cfg := aws.Config{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(),
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	}
	records, err := listLambda(context.Background(), cfg)
	if err != nil || len(records) != 1 || records[0].Resource == nil {
		t.Fatalf("Lambda records=%+v err=%v", records, err)
	}
	attributes := records[0].Resource.Attributes
	if attributes["runtime"] != "python3.13" || attributes["source_kms_key_arn"] != "arn:aws:kms:us-east-1:123456789012:key/code" || attributes["image_uri"] != image || attributes["resolved_image_uri"] != resolved {
		t.Fatalf("GetFunction attributes=%#v", attributes)
	}
	if _, ok := attributes["environment"]; ok {
		t.Fatal("raw environment must not be emitted")
	}
	if _, ok := attributes["location"]; ok {
		t.Fatal("presigned download URL must not be emitted")
	}
	if len(records[0].Resource.Tags) != 0 {
		t.Fatal("unvalidated tags must not be emitted")
	}
	if serialized := fmt.Sprintf("%+v", records); strings.Contains(serialized, "raw-secret") || strings.Contains(serialized, "download.example") {
		t.Fatal("Lambda records contain environment values or package URL")
	}
}
