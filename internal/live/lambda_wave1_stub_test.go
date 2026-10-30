// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// wave1LambdaStubConfig serves the shared Lambda fixture rows as Lambda
// REST-JSON responses. It serializes the same fixture bytes the in-tree
// oracle unmarshals directly, so a stub shape bug shows as a satellite miss
// (fix the stub), never as a production edit.
func wave1LambdaStubConfig(t *testing.T, fixture wave1LambdaFixture) aws.Config {
	t.Helper()

	byARN := map[string]wave1LambdaRow{}
	byName := map[string]wave1LambdaRow{}
	for _, function := range fixture.Functions {
		byARN[function.ARN] = function
		byName[function.Name] = function
	}
	aliasesByFunction := map[string][]wave1LambdaAlias{}
	for _, alias := range fixture.Aliases {
		aliasesByFunction[alias.FunctionName] = append(aliasesByFunction[alias.FunctionName], alias)
	}
	mappingsByFunction := map[string][]wave1LambdaMapping{}
	for _, mapping := range fixture.Mappings {
		mappingsByFunction[mapping.FunctionName] = append(mappingsByFunction[mapping.FunctionName], mapping)
	}

	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal stub response: %v", err)
		}
		return string(raw)
	}
	configurationDoc := func(row wave1LambdaRow, withSecrets bool) map[string]any {
		doc := map[string]any{
			"FunctionName": row.Name, "FunctionArn": row.ARN, "Runtime": row.Runtime,
			"Role": row.RoleARN, "Handler": row.Handler, "Description": row.Description,
			"State": row.State, "LastUpdateStatus": row.LastUpdateStatus,
			"PackageType": row.PackageType, "Version": row.Version,
			"CodeSha256": row.CodeSHA256, "CodeSize": row.CodeSize,
			"MemorySize": row.MemorySize, "Timeout": row.TimeoutSeconds,
			"Architectures": row.Architectures,
			"VpcConfig": map[string]any{
				"VpcId": row.VPCConfig.VPCID, "SubnetIds": row.VPCConfig.SubnetIDs,
				"SecurityGroupIds":        row.VPCConfig.SecurityGroupIDs,
				"Ipv6AllowedForDualStack": row.VPCConfig.IPv6AllowedForDS,
			},
			"LoggingConfig": map[string]any{
				"LogGroup": row.LoggingConfig.LogGroup, "LogFormat": row.LoggingConfig.LogFormat,
				"ApplicationLogLevel": row.LoggingConfig.ApplicationLogLevel,
				"SystemLogLevel":      row.LoggingConfig.SystemLogLevel,
			},
		}
		// A zero fixture time exercises the absent-field path: the API shape
		// carries no value and both sides map it to nil.
		if !row.LastModified.IsZero() {
			doc["LastModified"] = row.LastModified.Format("2006-01-02T15:04:05.000-0700")
		}
		// Environment rides the GetFunction response only: the satellite must
		// never emit its values, and the payload-branches test proves it.
		if withSecrets && len(row.Environment) != 0 {
			doc["Environment"] = map[string]any{"Variables": row.Environment}
		}
		return doc
	}
	getFunctionDoc := func(row wave1LambdaRow) string {
		doc := map[string]any{"Configuration": configurationDoc(row, true)}
		if row.ImageURI != "" || row.ResolvedImageURI != "" {
			doc["Code"] = map[string]any{
				"ImageUri": row.ImageURI, "ResolvedImageUri": row.ResolvedImageURI,
			}
		}
		doc["Tags"] = row.Tags
		return encode(doc)
	}
	aliasDoc := func(row wave1LambdaAlias) map[string]any {
		doc := map[string]any{
			"Name": row.Name, "FunctionVersion": row.FunctionVersion,
			"Description": row.Description, "RevisionId": row.RevisionID,
		}
		if row.ARN != "" {
			doc["AliasArn"] = row.ARN
		}
		if row.RoutingWeights != nil {
			doc["RoutingConfig"] = map[string]any{"AdditionalVersionWeights": row.RoutingWeights}
		}
		return doc
	}
	mappingDoc := func(row wave1LambdaMapping) map[string]any {
		doc := map[string]any{
			"UUID": row.UUID, "EventSourceArn": row.EventSourceARN, "State": row.State,
			"LastProcessingResult": row.LastProcessingResult, "StartingPosition": row.StartingPosition,
			"BatchSize": row.BatchSize, "MaximumRetryAttempts": row.MaximumRetryAttempts,
			"ParallelizationFactor": row.ParallelizationFactor,
		}
		if row.ARN != "" {
			doc["EventSourceMappingArn"] = row.ARN
		}
		if row.FunctionARN != "" {
			doc["FunctionArn"] = row.FunctionARN
		}
		return doc
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve := func(body string) {
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write stub response: %v", err)
			}
		}
		path := r.URL.Path
		switch {
		case path == "/2015-03-31/functions":
			functions := make([]map[string]any, 0, len(fixture.Functions))
			for _, row := range fixture.Functions {
				functions = append(functions, configurationDoc(row, false))
			}
			serve(encode(map[string]any{"Functions": functions}))
		case strings.HasSuffix(path, "/aliases"):
			functionID := strings.TrimSuffix(strings.TrimPrefix(path, "/2015-03-31/functions/"), "/aliases")
			row, ok := byARN[functionID]
			if !ok {
				if named, found := byName[functionID]; found {
					row = named
				} else {
					t.Errorf("unknown function %q", functionID)
					w.WriteHeader(http.StatusNotFound)
					return
				}
			}
			aliases := []map[string]any{}
			for _, alias := range aliasesByFunction[row.Name] {
				aliases = append(aliases, aliasDoc(alias))
			}
			serve(encode(map[string]any{"Aliases": aliases}))
		case strings.HasPrefix(path, "/2015-03-31/functions/"):
			functionID := strings.TrimPrefix(path, "/2015-03-31/functions/")
			row, ok := byARN[functionID]
			if !ok {
				if named, found := byName[functionID]; found {
					row = named
				} else {
					t.Errorf("unknown function %q", functionID)
					w.WriteHeader(http.StatusNotFound)
					return
				}
			}
			serve(getFunctionDoc(row))
		case path == "/2015-03-31/event-source-mappings":
			functionID := r.URL.Query().Get("FunctionName")
			row, ok := byARN[functionID]
			if !ok {
				if named, found := byName[functionID]; found {
					row = named
				} else {
					t.Errorf("unknown function %q", functionID)
					w.WriteHeader(http.StatusNotFound)
					return
				}
			}
			mappings := []map[string]any{}
			for _, mapping := range mappingsByFunction[row.Name] {
				mappings = append(mappings, mappingDoc(mapping))
			}
			serve(encode(map[string]any{"EventSourceMappings": mappings}))
		default:
			t.Errorf("unexpected Lambda request: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return aws.Config{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	}
}
