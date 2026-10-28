// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-sdk/factschema"
)

const historicalResourceKey = "6734b22d6e0d6d006d039191b646a44444ceffc8e176b312545ff739567a9b0f"

type resourceParityFixture struct {
	ScopeID             string `json:"scope_id"`
	GenerationID        string `json:"generation_id"`
	CollectorInstanceID string `json:"collector_instance_id"`
	Resource            struct {
		ARN                string            `json:"arn"`
		ResourceID         string            `json:"resource_id"`
		ResourceType       string            `json:"resource_type"`
		Name               string            `json:"name"`
		State              string            `json:"state"`
		Tags               map[string]string `json:"tags"`
		Attributes         map[string]any    `json:"attributes"`
		CorrelationAnchors []string          `json:"correlation_anchors"`
	} `json:"resource"`
}

func loadResourceParityFixture(t *testing.T) resourceParityFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/8852-parity-awscloud.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture resourceParityFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func resourceParityObservation(t *testing.T) ResourceObservation {
	t.Helper()
	fixture := loadResourceParityFixture(t)
	return ResourceObservation{
		Boundary: Boundary{
			AccountID: "123456789012", Region: "us-east-1", ServiceKind: "iam",
			ScopeID: fixture.ScopeID, GenerationID: fixture.GenerationID,
			CollectorInstanceID: fixture.CollectorInstanceID, FencingToken: 7,
			ObservedAt: time.Date(2026, 10, 20, 13, 0, 0, 0, time.UTC),
		},
		ARN: fixture.Resource.ARN, ResourceID: fixture.Resource.ResourceID,
		ResourceType: fixture.Resource.ResourceType, Name: fixture.Resource.Name,
		State: fixture.Resource.State, Tags: fixture.Resource.Tags,
		Attributes:         fixture.Resource.Attributes,
		CorrelationAnchors: fixture.Resource.CorrelationAnchors,
		SourceURI:          "aws:iam:role/parity-runtime", SourceRecordID: "role-row-1",
	}
}

func TestResourceFactHistoricalFixtureParity(t *testing.T) {
	observation := resourceParityObservation(t)
	fact, err := NewResourceFact(observation)
	if err != nil {
		t.Fatal(err)
	}
	if fact.Kind != AWSKindResource || fact.SchemaVersion != "1.0.0" || fact.StableKey != historicalResourceKey {
		t.Fatalf("fact identity = %q %q %q", fact.Kind, fact.SchemaVersion, fact.StableKey)
	}
	if fact.SourceConfidence != "reported" || !fact.ObservedAt.Equal(observation.Boundary.ObservedAt) {
		t.Fatalf("confidence/time = %q %v", fact.SourceConfidence, fact.ObservedAt)
	}
	if fact.SourceRef.SourceSystem != "aws" || fact.SourceRef.ScopeID != observation.Boundary.ScopeID || fact.SourceRef.GenerationID != observation.Boundary.GenerationID || fact.SourceRef.FactKey != fact.StableKey || fact.SourceRef.URI != observation.SourceURI || fact.SourceRef.RecordID != observation.SourceRecordID {
		t.Fatalf("source identity = %+v", fact.SourceRef)
	}
	expected := map[string]any{
		"account_id": "123456789012", "region": "us-east-1", "service_kind": "iam",
		"collector_instance_id": "aws-parity-8852", "arn": observation.ARN,
		"resource_id": observation.ResourceID, "resource_type": observation.ResourceType,
		"name": observation.Name, "state": observation.State, "tags": observation.Tags,
		"attributes":          observation.Attributes,
		"correlation_anchors": []string{observation.ARN, observation.ResourceID},
	}
	gotJSON, err := json.Marshal(fact.Payload)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("payload = %s, want %s", gotJSON, wantJSON)
	}
	decoded, err := factschema.DecodeAWSResource(factschema.Envelope{FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload})
	if err != nil || decoded.ResourceID != observation.ResourceID {
		t.Fatalf("typed decode = %+v, %v", decoded, err)
	}
	missingIdentity := make(map[string]any, len(fact.Payload))
	for key, value := range fact.Payload {
		missingIdentity[key] = value
	}
	delete(missingIdentity, "resource_id")
	_, err = factschema.DecodeAWSResource(factschema.Envelope{FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: missingIdentity})
	var decodeErr *factschema.DecodeError
	if !errors.As(err, &decodeErr) || decodeErr.Classification != factschema.ClassificationInputInvalid || decodeErr.Field != "resource_id" {
		t.Fatalf("missing resource_id decode error = %v, want classified input_invalid", err)
	}
	rotated := observation
	rotated.Boundary.GenerationID += ":2"
	rotatedFact, err := NewResourceFact(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if rotatedFact.StableKey != fact.StableKey || rotatedFact.SourceRef.GenerationID != rotated.Boundary.GenerationID {
		t.Fatalf("rotated fact = %+v", rotatedFact)
	}
}

func TestResourceFactAnchorNormalizationAndFallback(t *testing.T) {
	observation := resourceParityObservation(t)
	observation.CorrelationAnchors = []string{"  extra  ", "", " extra", " " + observation.ARN + " ", observation.ResourceID}
	fact, err := NewResourceFact(observation)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"extra", observation.ARN, observation.ResourceID}
	if got := fact.Payload["correlation_anchors"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("anchors = %#v, want %#v", got, want)
	}
	observation.ARN = " " + observation.ARN + " "
	observation.ResourceID = "  "
	observation.SourceRecordID = "  "
	observation.CorrelationAnchors = nil
	fact, err = NewResourceFact(observation)
	if err != nil {
		t.Fatal(err)
	}
	if fact.Payload["resource_id"] != strings.TrimSpace(observation.ARN) || fact.SourceRef.RecordID != strings.TrimSpace(observation.ARN) {
		t.Fatalf("ARN fallback = %#v, source = %+v", fact.Payload["resource_id"], fact.SourceRef)
	}
	if got := fact.Payload["correlation_anchors"]; !reflect.DeepEqual(got, []string{strings.TrimSpace(observation.ARN)}) {
		t.Fatalf("fallback anchors = %#v", got)
	}
	observation.ResourceID = "bare-id"
	observation.ARN = "  "
	fact, err = NewResourceFact(observation)
	if err != nil {
		t.Fatal(err)
	}
	if got := fact.Payload["correlation_anchors"]; !reflect.DeepEqual(got, []string{"bare-id"}) {
		t.Fatalf("bare ID anchors = %#v", got)
	}
}

func TestResourceFactEmptyOptionalFields(t *testing.T) {
	observation := resourceParityObservation(t)
	observation.Tags = nil
	observation.Attributes = nil
	observation.CorrelationAnchors = nil
	observation.Name = ""
	observation.State = ""
	fact, err := NewResourceFact(observation)
	if err != nil {
		t.Fatal(err)
	}
	if fact.StableKey != historicalResourceKey {
		t.Fatalf("optional fields changed stable key: %q", fact.StableKey)
	}
	if tags, present := fact.Payload["tags"]; !present || !reflect.DeepEqual(tags, map[string]string(nil)) {
		t.Fatalf("empty tags = %#v, present = %v; want legacy nil map", tags, present)
	}
	if attributes, present := fact.Payload["attributes"]; !present || !reflect.DeepEqual(attributes, map[string]any(nil)) {
		t.Fatalf("empty attributes = %#v, present = %v; want legacy nil map", attributes, present)
	}
	if got := fact.Payload["correlation_anchors"]; !reflect.DeepEqual(got, []string{observation.ARN, observation.ResourceID}) {
		t.Fatalf("empty anchor fallback = %#v", got)
	}
}

func TestResourceFactCarriesLegacyRedactedOutputShape(t *testing.T) {
	observation := resourceParityObservation(t)
	observation.Attributes = map[string]any{
		"outputs": []map[string]any{{
			"key": "DatabasePassword",
			"redacted": map[string]any{
				"marker": "redacted:hmac-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"reason": "known-sensitive-key",
			},
		}},
	}
	fact, err := NewResourceFact(observation)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(fact.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "DatabasePassword") || !strings.Contains(string(raw), "redacted:hmac-sha256:") || strings.Contains(string(raw), "hunter2-parity-secret") {
		t.Fatalf("redacted output transport = %s", raw)
	}
	if _, err := factschema.DecodeAWSResource(factschema.Envelope{FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload}); err != nil {
		t.Fatalf("typed decode redacted output: %v", err)
	}
}

func TestResourceFactRejectsInvalidAndUnredactedInputs(t *testing.T) {
	base := resourceParityObservation(t)
	cases := []struct {
		name   string
		mutate func(*ResourceObservation)
	}{
		{"no identity", func(o *ResourceObservation) { o.ARN = " "; o.ResourceID = " " }},
		{"no type", func(o *ResourceObservation) { o.ResourceType = " " }},
		{"no account", func(o *ResourceObservation) { o.Boundary.AccountID = " " }},
		{"no region", func(o *ResourceObservation) { o.Boundary.Region = " " }},
		{"no service", func(o *ResourceObservation) { o.Boundary.ServiceKind = " " }},
		{"no scope", func(o *ResourceObservation) { o.Boundary.ScopeID = " " }},
		{"no generation", func(o *ResourceObservation) { o.Boundary.GenerationID = " " }},
		{"no instance", func(o *ResourceObservation) { o.Boundary.CollectorInstanceID = " " }},
		{"no fence", func(o *ResourceObservation) { o.Boundary.FencingToken = 0 }},
		{"empty URI", func(o *ResourceObservation) { o.SourceURI = " " }},
		{"unsafe URI", func(o *ResourceObservation) { o.SourceURI = "https://user:secret@example.invalid/" }},
		{"non-JSON attribute", func(o *ResourceObservation) { o.Attributes = map[string]any{"callback": func() {}} }},
		{"raw secret attribute", func(o *ResourceObservation) {
			o.Attributes = map[string]any{"DatabasePassword": "hunter2-parity-secret"}
		}},
		{"redacted secret attribute key", func(o *ResourceObservation) {
			o.Attributes = map[string]any{"DatabasePassword": map[string]any{"marker": "redacted"}}
		}},
		{"nested secret attribute key", func(o *ResourceObservation) {
			o.Attributes = map[string]any{"settings": map[string]string{"DatabasePassword": "hunter2-parity-secret"}}
		}},
		{"secret tag key", func(o *ResourceObservation) {
			o.Tags = map[string]string{"DatabasePassword": "hunter2-parity-secret"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			observation := base
			tc.mutate(&observation)
			fact, err := NewResourceFact(observation)
			if err == nil || fact.Kind != "" {
				t.Fatalf("fact = %+v, error = %v; want no fact and error", fact, err)
			}
		})
	}
}

func TestResourceFactRejectsPresignedSourceURIWithoutEcho(t *testing.T) {
	uris := []string{
		"https://bucket.s3.amazonaws.com/key?X-Amz-Credential=AKIAEXAMPLE%2F20261028%2Fus-east-1%2Fs3%2Faws4_request",
		"https://bucket.s3.amazonaws.com/key?X-Amz-Signature=deadbeefsecret",
		"https://bucket.s3.amazonaws.com/key?X-Amz-%43redential=AKIAEXAMPLE",
	}
	for _, uri := range uris {
		t.Run(uri[:strings.IndexByte(uri, '?')], func(t *testing.T) {
			observation := resourceParityObservation(t)
			observation.SourceURI = uri
			fact, err := NewResourceFact(observation)
			if err == nil || fact.Kind != "" {
				t.Fatalf("presigned URI fact = %+v, error = %v; want refusal", fact, err)
			}
			if strings.Contains(err.Error(), "AKIAEXAMPLE") || strings.Contains(err.Error(), "deadbeefsecret") || strings.Contains(err.Error(), uri) {
				t.Fatalf("error echoed credential material: %v", err)
			}
		})
	}
}

func TestResourceFactCopiesNestedJSONValuesBeforeValidation(t *testing.T) {
	observation := resourceParityObservation(t)
	const exactID int64 = 9007199254740993
	names := []string{"first"}
	levels := []int{1, 2}
	values := []map[string]any{{
		"count":  exactID,
		"names":  names,
		"levels": levels,
	}}
	nested := map[string]any{"rows": values}
	observation.Attributes = map[string]any{"nested": nested}
	fact, err := NewResourceFact(observation)
	if err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(fact.Payload)
	if err != nil {
		t.Fatal(err)
	}
	values[0]["count"] = int64(1)
	names[0] = "changed"
	levels[0] = 9
	values[0]["DatabasePassword"] = "hunter2-parity-secret"
	nested["injected"] = "changed"
	observation.Tags["Environment"] = "changed"
	after, err := json.Marshal(fact.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("payload changed after caller mutation: before %s, after %s", before, after)
	}
	attributes, ok := fact.Payload["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("attributes type = %T", fact.Payload["attributes"])
	}
	gotNested, ok := attributes["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested type = %T", attributes["nested"])
	}
	rows, ok := gotNested["rows"].([]map[string]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("rows = %#v", gotNested["rows"])
	}
	if count, ok := rows[0]["count"].(int64); !ok || count != exactID {
		t.Fatalf("count = %#v, want exact int64 %d", rows[0]["count"], exactID)
	}
}
