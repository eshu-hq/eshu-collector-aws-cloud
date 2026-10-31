// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// wave1KMSStubConfig serves the shared KMS fixture rows as KMS JSON-protocol
// responses, routed on the X-Amz-Target operation header. It serializes the
// same fixture bytes the in-tree oracle unmarshals directly, so a stub shape
// bug shows as a satellite miss (fix the stub), never as a production edit.
// List responses paginate so the production paginators are always exercised.
// One extra target-less alias rides the second alias page: it can never join
// a key, proving the production drop path instead of the oracle inputs.
func wave1KMSStubConfig(t *testing.T, fixture wave1KMSFixture) aws.Config {
	t.Helper()

	byID := map[string]wave1KMSRow{}
	for _, key := range fixture.Keys {
		byID[key.ID] = key
	}
	var allAliases []wave1KMSAlias
	for _, key := range fixture.Keys {
		allAliases = append(allAliases, key.Aliases...)
	}

	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal stub response: %v", err)
		}
		return string(raw)
	}
	epoch := func(value string) any {
		if strings.TrimSpace(value) == "" {
			return nil
		}
		moment, err := time.Parse(time.RFC3339, value)
		if err != nil {
			t.Fatalf("parse stub time %q: %v", value, err)
		}
		return float64(moment.Unix())
	}
	keyMetadataDoc := func(row wave1KMSRow) map[string]any {
		doc := map[string]any{
			"KeyId": row.ID, "Arn": row.ARN, "Description": row.Description,
			"KeyManager": row.KeyManager, "KeyUsage": row.KeyUsage, "KeySpec": row.KeySpec,
			"KeyState": row.KeyState, "Origin": row.Origin, "Enabled": row.Enabled,
			"MultiRegion":          row.MultiRegion,
			"EncryptionAlgorithms": row.EncryptionAlgorithms, "SigningAlgorithms": row.SigningAlgorithms,
			"MacAlgorithms": row.MACAlgorithms, "KeyAgreementAlgorithms": row.KeyAgreementAlgorithms,
		}
		if created := epoch(row.CreationDate); created != nil {
			doc["CreationDate"] = created
		}
		if deleted := epoch(row.DeletionDate); deleted != nil {
			doc["DeletionDate"] = deleted
		}
		if row.MultiRegion {
			config := map[string]any{"MultiRegionKeyType": row.MultiRegionKeyType}
			if strings.TrimSpace(row.PrimaryKeyARN) != "" {
				config["PrimaryKey"] = map[string]any{"Arn": row.PrimaryKeyARN}
			}
			doc["MultiRegionConfiguration"] = config
		}
		return doc
	}
	aliasDoc := func(row wave1KMSAlias) map[string]any {
		doc := map[string]any{"AliasName": row.Name, "TargetKeyId": row.TargetKeyID}
		if strings.TrimSpace(row.ARN) != "" {
			doc["AliasArn"] = row.ARN
		}
		if updated := epoch(row.LastUpdated); updated != nil {
			doc["LastUpdatedDate"] = updated
		}
		return doc
	}
	grantDoc := func(keyID string, row wave1KMSGrant) map[string]any {
		doc := map[string]any{"KeyId": keyID, "GrantId": row.ID, "IssuingAccount": row.IssuingAccount}
		if strings.TrimSpace(row.Name) != "" {
			doc["Name"] = row.Name
		}
		if created := epoch(row.CreationDate); created != nil {
			doc["CreationDate"] = created
		}
		switch row.GranteePrincipalType {
		case "AWS":
			doc["GranteePrincipal"] = row.GranteePrincipal
		case "Service":
			doc["GranteeServicePrincipal"] = row.GranteePrincipal
		}
		switch row.RetiringPrincipalType {
		case "AWS":
			doc["RetiringPrincipal"] = row.RetiringPrincipal
		case "Service":
			doc["RetiringServicePrincipal"] = row.RetiringPrincipal
		}
		if len(row.Operations) != 0 {
			doc["Operations"] = row.Operations
		}
		return doc
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve := func(body string) {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write stub response: %v", err)
			}
		}
		serveDoc := func(doc map[string]any) { serve(encode(doc)) }
		rawBody, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read stub request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var body map[string]any
		if len(rawBody) != 0 {
			if err := json.Unmarshal(rawBody, &body); err != nil {
				t.Errorf("decode stub request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		marker, ok := body["Marker"].(string)
		if !ok {
			marker = ""
		}
		target := r.Header.Get("X-Amz-Target")
		switch {
		case strings.HasSuffix(target, "ListKeys"):
			entries := []map[string]any{}
			for _, key := range fixture.Keys {
				entries = append(entries, map[string]any{"KeyId": key.ID, "KeyArn": key.ARN})
			}
			if marker == "" && len(entries) > 2 {
				serveDoc(map[string]any{"Keys": entries[:2], "Truncated": true, "NextMarker": "page2"})
				return
			}
			if marker == "page2" {
				entries = entries[2:]
			} else if marker != "" {
				t.Errorf("unexpected ListKeys marker %q", marker)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			serveDoc(map[string]any{"Keys": entries, "Truncated": false})
		case strings.HasSuffix(target, "DescribeKey"):
			id, ok := body["KeyId"].(string)
			if !ok {
				t.Errorf("stub request missing KeyId")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			row, ok := byID[strings.TrimSpace(id)]
			if !ok {
				t.Errorf("unknown key %q", id)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			serveDoc(map[string]any{"KeyMetadata": keyMetadataDoc(row)})
		case strings.HasSuffix(target, "ListAliases"):
			entries := []map[string]any{}
			for _, alias := range allAliases {
				entries = append(entries, aliasDoc(alias))
			}
			entries = append(entries, map[string]any{"AliasName": "alias/wave1-unattached"})
			if marker == "" {
				serveDoc(map[string]any{"Aliases": entries[:2], "Truncated": true, "NextMarker": "page2"})
				return
			}
			if marker == "page2" {
				entries = entries[2:]
			} else {
				t.Errorf("unexpected ListAliases marker %q", marker)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			serveDoc(map[string]any{"Aliases": entries, "Truncated": false})
		case strings.HasSuffix(target, "ListGrants"):
			id, ok := body["KeyId"].(string)
			if !ok {
				t.Errorf("stub request missing KeyId")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			row, ok := byID[strings.TrimSpace(id)]
			if !ok {
				t.Errorf("unknown key %q", id)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			entries := []map[string]any{}
			for _, grant := range row.Grants {
				entries = append(entries, grantDoc(row.ID, grant))
			}
			if marker == "" && len(entries) > 1 {
				serveDoc(map[string]any{"Grants": entries[:1], "Truncated": true, "NextMarker": "g2"})
				return
			}
			if marker == "g2" {
				entries = entries[1:]
			} else if marker != "" {
				t.Errorf("unexpected ListGrants marker %q", marker)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			serveDoc(map[string]any{"Grants": entries, "Truncated": false})
		default:
			t.Errorf("unexpected KMS request target %q", target)
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
