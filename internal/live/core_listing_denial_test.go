// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// Seeded RED/GREEN proof for #9297: a 403 on a core listing call in any of
// the four reviewed services stays terminal. The loader must return a plain
// error (never *optionalReadDenied, which is reserved for the four named
// optional enrichments), contribute no evidence, and fail a single-service
// claim at CollectReport because nothing is readable.

func coreTerminalCollector(t *testing.T, cfg aws.Config, service string, load Loader) Collector {
	t.Helper()
	return Collector{
		LoadConfig: func(context.Context, string) (aws.Config, error) { return cfg, nil },
		VerifyIdentity: func(context.Context, aws.Config) (VerifiedIdentity, error) {
			return VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}, nil
		},
		Loaders: map[string]Loader{service: load},
	}
}

func assertCoreDenialTerminal(t *testing.T, service, operation string, records []collector.Record, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s core denial succeeded, want terminal failure", service)
	}
	var denied *optionalReadDenied
	if errors.As(err, &denied) {
		t.Fatalf("%s core denial degraded to optional: %v", service, err)
	}
	if len(records) != 0 {
		t.Fatalf("%s core denial kept %d records, want none", service, len(records))
	}
	if !strings.Contains(err.Error(), operation) {
		t.Fatalf("%s core error %q does not name %q", service, err, operation)
	}
}

func assertSingleServiceClaimFails(t *testing.T, service string, reader Collector) {
	t.Helper()
	_, err := reader.CollectReport(context.Background(), Config{
		AccountID: "123456789012", Regions: []string{"us-east-1"}, Services: []string{service},
	})
	if err == nil {
		t.Fatalf("%s core denial left the claim readable, want terminal failure", service)
	}
}

// writeTestBody fails the test when the fake AWS endpoint cannot answer,
// so a broken fixture server never masquerades as a service denial.
func writeTestBody(t *testing.T, w http.ResponseWriter, format string, args ...any) {
	t.Helper()
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		t.Errorf("test server write: %v", err)
	}
}

func testConfigForServer(t *testing.T, server *httptest.Server) aws.Config {
	t.Helper()
	return aws.Config{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(),
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	}
}

func TestEC2CoreListingDenialStaysTerminal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		action := r.Form.Get("Action")
		w.Header().Set("Content-Type", "text/xml")
		if action == "DescribeInstances" {
			w.WriteHeader(http.StatusForbidden)
			writeTestBody(t, w, `<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>denied</Message></Error></Errors><RequestID>x</RequestID></Response>`)
			return
		}
		writeTestBody(t, w, `<%sResponse><requestId>x</requestId></%sResponse>`, action, action)
	}))
	defer server.Close()
	cfg := testConfigForServer(t, server)
	records, err := listEC2(context.Background(), cfg, VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	assertCoreDenialTerminal(t, "ec2", "ec2 describe instances", records, err)
	assertSingleServiceClaimFails(t, "ec2", coreTerminalCollector(t, cfg, "ec2", listEC2))
}

func TestEKSCoreListingDenialStaysTerminal(t *testing.T) {
	calls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls[r.URL.Path]++
		if r.URL.Path == "/clusters" && r.Method == http.MethodGet {
			w.Header().Set("X-Amzn-ErrorType", "AccessDeniedException")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			writeTestBody(t, w, `{"message":"denied"}`)
			return
		}
		t.Errorf("unexpected EKS request after core denial: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	cfg := testConfigForServer(t, server)
	records, err := listEKS(context.Background(), cfg, VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	assertCoreDenialTerminal(t, "eks", "eks list clusters", records, err)
	if calls["/clusters"] == 0 {
		t.Fatalf("core ListClusters was never attempted: %v", calls)
	}
	assertSingleServiceClaimFails(t, "eks", coreTerminalCollector(t, cfg, "eks", listEKS))
}

func TestLambdaCoreListingDenialStaysTerminal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/2015-03-31/functions" {
			w.Header().Set("X-Amzn-Errortype", "AccessDeniedException")
			w.WriteHeader(http.StatusForbidden)
			writeTestBody(t, w, `{"Type":"AccessDeniedException","message":"denied"}`)
			return
		}
		t.Errorf("unexpected Lambda request after core denial: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	cfg := testConfigForServer(t, server)
	records, err := listLambda(context.Background(), cfg)
	assertCoreDenialTerminal(t, "lambda", "lambda list functions", records, err)
	assertSingleServiceClaimFails(t, "lambda", coreTerminalCollector(t, cfg, "lambda", func(ctx context.Context, config aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
		return listLambda(ctx, config)
	}))
}

func TestS3CoreListingDenialStaysTerminal(t *testing.T) {
	denied := &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}
	api := &fakeS3BucketDetails{listErr: denied}
	identity := VerifiedIdentity{AccountID: "123456789012", Partition: "aws"}
	records, err := listS3WithAPI(context.Background(), api, "us-east-1", identity)
	assertCoreDenialTerminal(t, "s3", "s3 list buckets", records, err)
	if !errors.Is(err, denied) {
		t.Fatalf("s3 core error %v does not wrap the listing denial", err)
	}
	reader := Collector{
		LoadConfig: func(_ context.Context, region string) (aws.Config, error) { return aws.Config{Region: region}, nil },
		VerifyIdentity: func(_ context.Context, _ aws.Config) (VerifiedIdentity, error) {
			return identity, nil
		},
		Loaders: map[string]Loader{"s3": func(ctx context.Context, _ aws.Config, _ VerifiedIdentity) ([]collector.Record, error) {
			return listS3WithAPI(ctx, api, "us-east-1", identity)
		}},
	}
	assertSingleServiceClaimFails(t, "s3", reader)
}
