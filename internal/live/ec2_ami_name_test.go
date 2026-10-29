// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// benignAMINames are real-shaped creator labels from the #9525 proof battery:
// Ubuntu, RHEL, Amazon Linux 2, Windows, and a golden image. Every entry fits
// the AWS CreateImage structural contract, so each must pass through producer
// emission verbatim with no warning.
//
// The admitted field stays untrusted creator-controlled text: admission claims
// structural validity only, never secret-freedom (see
// TestAMINameBareTokenPassesDocumented).
var benignAMINames = []string{
	"ubuntu-jammy-22.04-amd64-server-20240115",
	"RHEL-9.3.0_HVM-20240115-x86_64-0-Hourly2-GP2",
	"amzn2-ami-kernel-5.10-hvm-2.0.20240115.0-x86_64-gp2",
	"Windows_Server-2022-English-Full-Base-2024.01.15",
	"golden-image-web-2024.01 (prod)",
}

// amiNamedImageXML serves one image carrying the given raw <name> element
// text alongside one typed field, so drop tests can prove the typed contract
// survives beside a dropped name.
func amiNamedImageXML(id, name string) string {
	return amiImageItem(id,
		`<architecture>x86_64</architecture>`+
			`<name>`+name+`</name>`)
}

// amiNameDenial extracts the single ami_name_dropped denial from a listEC2
// error, failing the test when the scan did not degrade exactly that way.
func amiNameDenial(t *testing.T, err error) optionalDenial {
	t.Helper()
	denied, ok := err.(*optionalReadDenied)
	if !ok {
		t.Fatalf("err = %T (%v), want *optionalReadDenied with ami_name_dropped", err, err)
	}
	if len(denied.denials) != 1 {
		t.Fatalf("denials = %#v, want exactly one deduped ami_name_dropped entry", denied.denials)
	}
	entry := denied.denials[0]
	if entry.operation != "DescribeImages" || entry.effect != "ami_name_dropped" {
		t.Fatalf("denial = %#v, want operation DescribeImages effect ami_name_dropped", entry)
	}
	return entry
}

func TestAMINameBenignRealShapesPassVerbatim(t *testing.T) {
	for _, name := range benignAMINames {
		t.Run(name, func(t *testing.T) {
			instances := amiInstancesXML(`<item><instanceId>i-1</instanceId><imageId>ami-benign</imageId></item>`)
			fixture := newAMITestServer(t, instances, map[string]string{
				"ami-benign": amiNamedImageXML("ami-benign", name),
			}, "")
			records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
			if err != nil {
				t.Fatalf("listEC2 = %v, want no warning for a benign name", err)
			}
			row := findAMIRecord(records, "ami-benign")
			if row == nil {
				t.Fatal("ami-benign record missing")
			}
			if got := row.Resource.Attributes["name"]; got != name {
				t.Fatalf("name = %#v, want verbatim %q", got, name)
			}
			if row.Resource.Attributes["architecture"] != "x86_64" {
				t.Fatalf("typed fields lost beside admitted name: %#v", row.Resource.Attributes)
			}
		})
	}
}

// TestAMINameBareTokenPassesDocumented pins the honesty of the "not
// secret-free" contract claim: a patternless token fits the AWS charset, trips
// no shared predicate, and is therefore ADMITTED. The admitted field is
// structurally valid creator text, never a safety verdict on its content.
func TestAMINameBareTokenPassesDocumented(t *testing.T) {
	const bareToken = "x7Qv9mK2pL4nB8dF1"
	instances := amiInstancesXML(`<item><instanceId>i-1</instanceId><imageId>ami-token</imageId></item>`)
	fixture := newAMITestServer(t, instances, map[string]string{
		"ami-token": amiNamedImageXML("ami-token", bareToken),
	}, "")
	records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatalf("listEC2 = %v, want no warning: the bare token is charset-valid", err)
	}
	row := findAMIRecord(records, "ami-token")
	if row == nil {
		t.Fatal("ami-token record missing")
	}
	if got := row.Resource.Attributes["name"]; got != bareToken {
		t.Fatalf("name = %#v, want the bare token verbatim (expected to pass)", got)
	}
}

func TestAMINameKeyValueShapesDropWithOneWarning(t *testing.T) {
	instances := amiInstancesXML(
		`<item><instanceId>i-1</instanceId><imageId>ami-kv1</imageId></item>` +
			`<item><instanceId>i-2</instanceId><imageId>ami-kv2</imageId></item>`)
	fixture := newAMITestServer(t, instances, map[string]string{
		"ami-kv1": amiNamedImageXML("ami-kv1", "db_password=hunter2"),
		"ami-kv2": amiNamedImageXML("ami-kv2", "api_key = sk-live-test"),
	}, "")
	records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	entry := amiNameDenial(t, err)
	if got := entry.attributes["dropped_count"]; got != 2 {
		t.Fatalf("dropped_count = %#v, want 2 for two key=value names in one scan", got)
	}
	for _, id := range []string{"ami-kv1", "ami-kv2"} {
		row := findAMIRecord(records, id)
		if row == nil {
			t.Fatalf("%s record missing", id)
		}
		if _, present := row.Resource.Attributes["name"]; present {
			t.Fatalf("%s name admitted, want dropped", id)
		}
		if row.Resource.Attributes["architecture"] != "x86_64" {
			t.Fatalf("%s typed fields lost beside dropped name: %#v", id, row.Resource.Attributes)
		}
	}
	diagnostics, marshalErr := json.Marshal(map[string]any{
		"message":    optionalDenialMessage(entry),
		"attributes": optionalDenialAttributes(entry),
	})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, raw := range []string{"hunter2", "sk-live-test"} {
		if strings.Contains(string(diagnostics), raw) {
			t.Fatalf("diagnostics carry raw text %q: %s", raw, diagnostics)
		}
	}
}

func TestAMINameOverCapDropped(t *testing.T) {
	name := strings.Repeat("a", 129)
	instances := amiInstancesXML(`<item><instanceId>i-1</instanceId><imageId>ami-long</imageId></item>`)
	fixture := newAMITestServer(t, instances, map[string]string{
		"ami-long": amiNamedImageXML("ami-long", name),
	}, "")
	records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	amiNameDenial(t, err)
	row := findAMIRecord(records, "ami-long")
	if row == nil {
		t.Fatal("ami-long record missing")
	}
	if _, present := row.Resource.Attributes["name"]; present {
		t.Fatal("129-rune name admitted, want dropped")
	}
	if row.Resource.Attributes["architecture"] != "x86_64" {
		t.Fatalf("typed fields lost beside dropped name: %#v", row.Resource.Attributes)
	}
}

func TestAMINameCharsetViolationDropped(t *testing.T) {
	const name = "my-image;rm -rf"
	instances := amiInstancesXML(`<item><instanceId>i-1</instanceId><imageId>ami-charset</imageId></item>`)
	fixture := newAMITestServer(t, instances, map[string]string{
		"ami-charset": amiNamedImageXML("ami-charset", name),
	}, "")
	records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	amiNameDenial(t, err)
	row := findAMIRecord(records, "ami-charset")
	if row == nil {
		t.Fatal("ami-charset record missing")
	}
	if _, present := row.Resource.Attributes["name"]; present {
		t.Fatalf("charset-violating name admitted, want dropped")
	}
}

func TestAMINameBlankOmittedWithoutWarning(t *testing.T) {
	instances := amiInstancesXML(`<item><instanceId>i-1</instanceId><imageId>ami-blank</imageId></item>`)
	fixture := newAMITestServer(t, instances, map[string]string{
		"ami-blank": amiNamedImageXML("ami-blank", "   "),
	}, "")
	records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatalf("listEC2 = %v, want no warning for a blank name (absent values stay omitted)", err)
	}
	row := findAMIRecord(records, "ami-blank")
	if row == nil {
		t.Fatal("ami-blank record missing")
	}
	if _, present := row.Resource.Attributes["name"]; present {
		t.Fatal("blank name admitted, want omitted")
	}
	if row.Resource.Attributes["architecture"] != "x86_64" {
		t.Fatalf("typed fields lost beside omitted name: %#v", row.Resource.Attributes)
	}
}

// TestAMINameEmittedAsJSONStringScalar pins the never-stringified discipline
// at the producer: the admitted name reaches stored/replayed payload bytes as
// a JSON string scalar, never a converted non-string.
func TestAMINameEmittedAsJSONStringScalar(t *testing.T) {
	const name = "ubuntu-jammy-22.04-amd64-server-20240115"
	instances := amiInstancesXML(`<item><instanceId>i-1</instanceId><imageId>ami-scalar</imageId></item>`)
	fixture := newAMITestServer(t, instances, map[string]string{
		"ami-scalar": amiNamedImageXML("ami-scalar", name),
	}, "")
	records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatalf("listEC2 = %v", err)
	}
	row := findAMIRecord(records, "ami-scalar")
	if row == nil {
		t.Fatal("ami-scalar record missing")
	}
	encoded, marshalErr := json.Marshal(row.Resource.Attributes)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	var decoded map[string]any
	if unmarshalErr := json.Unmarshal(encoded, &decoded); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	got, ok := decoded["name"].(string)
	if !ok {
		t.Fatalf("payload name = %#v, want a JSON string scalar", decoded["name"])
	}
	if got != name {
		t.Fatalf("payload name = %q, want verbatim %q", got, name)
	}
}

func TestAMINameDiagnosticsNeverCarryRawText(t *testing.T) {
	const name = "db_password=hunter2-fleet"
	instances := amiInstancesXML(`<item><instanceId>i-1</instanceId><imageId>ami-diag</imageId></item>`)
	fixture := newAMITestServer(t, instances, map[string]string{
		"ami-diag": amiNamedImageXML("ami-diag", name),
	}, "")
	_, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	entry := amiNameDenial(t, err)
	diagnostics, marshalErr := json.Marshal(map[string]any{
		"message":    optionalDenialMessage(entry),
		"attributes": optionalDenialAttributes(entry),
	})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, raw := range []string{name, "hunter2-fleet"} {
		if strings.Contains(string(diagnostics), raw) {
			t.Fatalf("diagnostics carry raw text %q: %s", raw, diagnostics)
		}
	}
}

// TestInspectAMINameReasons pins the validator's fail-closed boundary per
// cause. Causes stay in unit tests only: scan diagnostics carry the effect and
// the dropped count, never a per-name reason or the raw text.
func TestInspectAMINameReasons(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantAdmit bool
		wantOmit  bool
		wantCause amiNameDropCause
	}{
		{name: "empty omits", input: "", wantOmit: true},
		{name: "blank omits", input: "   ", wantOmit: true},
		{name: "below minimum drops", input: "ab", wantCause: amiNameDropLength},
		{name: "minimum admits", input: "abc", wantAdmit: true},
		{name: "maximum admits", input: strings.Repeat("a", 128), wantAdmit: true},
		{name: "over maximum drops", input: strings.Repeat("a", 129), wantCause: amiNameDropLength},
		{name: "key=value drops on hygiene", input: "db_password=hunter2", wantCause: amiNameDropHygiene},
		{name: "spaced key=value drops on hygiene", input: "api_key = sk-live", wantCause: amiNameDropHygiene},
		{name: "header pair drops on hygiene", input: "Authorization: Bearer abc", wantCause: amiNameDropHygiene},
		{name: "authorization pair drops on hygiene", input: "authorization=abc123", wantCause: amiNameDropHygiene},
		{name: "marker word drops on hygiene", input: "my-password-reset-image", wantCause: amiNameDropHygiene},
		{name: "clean colon drops on charset", input: "image:v2", wantCause: amiNameDropCharset},
		{name: "semicolon drops on charset", input: "my-image;rm -rf", wantCause: amiNameDropCharset},
		// XML transport cannot carry a control character (it is not legal
		// XML 1.0), so this leg only runs at the validator: the producer
		// rejects controls even if an SDK surface ever surfaces one.
		{name: "control drops on charset", input: "bad\x00name", wantCause: amiNameDropCharset},
		{name: "non-ascii drops on charset", input: "café-serveur-2024", wantCause: amiNameDropCharset},
		{name: "benign admits", input: "ubuntu-jammy-22.04-amd64-server-20240115", wantAdmit: true},
		{name: "bare token admits", input: "x7Qv9mK2pL4nB8dF1", wantAdmit: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := inspectAMIName(tc.input)
			if result.admit != tc.wantAdmit || result.omit != tc.wantOmit {
				t.Fatalf("inspectAMIName(%q) = %+v, want admit=%v omit=%v", tc.input, result, tc.wantAdmit, tc.wantOmit)
			}
			if !tc.wantAdmit && !tc.wantOmit && result.cause != tc.wantCause {
				t.Fatalf("inspectAMIName(%q) cause = %q, want %q", tc.input, result.cause, tc.wantCause)
			}
			if tc.wantAdmit && result.value != tc.input {
				t.Fatalf("admitted value = %q, want verbatim %q", result.value, tc.input)
			}
		})
	}
}
