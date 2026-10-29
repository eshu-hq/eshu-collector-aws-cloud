// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// adversarialAMIName and adversarialAMIDescription carry secret-shaped and
// private-identifier values an image creator could publish. They must never
// surface through producer emission (see eshu-hq/eshu#9525).
const (
	adversarialAMIName        = "legacy-php-5.6 AKIAIOSFODNN7EXAMPLE"
	adversarialAMIDescription = "db_password=hunter2; owner jdoe@corp.example -- internal only, do not share"
)

type amiTestServer struct {
	server        *httptest.Server
	calls         map[string]int
	describeQuery url.Values
}

func amiTestConfig(server *httptest.Server) aws.Config {
	return aws.Config{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(),
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	}
}

func amiInstancesXML(items string) string {
	return `<DescribeInstancesResponse><requestId>x</requestId><reservationSet><item><reservationId>r-1</reservationId><instancesSet>` +
		items + `</instancesSet></item></reservationSet></DescribeInstancesResponse>`
}

func amiImageItem(id, body string) string {
	return `<item><imageId>` + id + `</imageId>` + body + `</item>`
}

// newAMITestServer serves DescribeInstances from instancesXML and
// DescribeImages from images (keyed by AMI id; absent ids read back as
// unresolved). describeErrCode non-empty fails DescribeImages with that EC2
// error code; every other action gets an empty response shell.
func newAMITestServer(t *testing.T, instancesXML string, images map[string]string, describeErrCode string) *amiTestServer {
	t.Helper()
	fixture := &amiTestServer{calls: map[string]int{}}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		action := r.Form.Get("Action")
		fixture.calls[action]++
		w.Header().Set("Content-Type", "text/xml")
		serve := func(body string) {
			if _, err := w.Write([]byte(body)); err != nil {
				t.Error(err)
			}
		}
		switch action {
		case "DescribeImages":
			fixture.describeQuery = r.Form
			if describeErrCode != "" {
				w.WriteHeader(http.StatusForbidden)
				serve(fmt.Sprintf(`<Response><Errors><Error><Code>%s</Code><Message>denied</Message></Error></Errors><RequestID>x</RequestID></Response>`, describeErrCode))
				return
			}
			// Like AWS, the fixture answers only requested ids; anything else
			// reads back as unresolved.
			requested := map[string]bool{}
			for key, values := range r.Form {
				if strings.HasPrefix(key, "ImageId.") {
					for _, value := range values {
						requested[value] = true
					}
				}
			}
			var set strings.Builder
			for id, item := range images {
				if requested[id] {
					set.WriteString(item)
				}
			}
			serve(fmt.Sprintf(`<DescribeImagesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>x</requestId><imagesSet>%s</imagesSet></DescribeImagesResponse>`, set.String()))
		case "DescribeInstances":
			serve(instancesXML)
		default:
			serve(fmt.Sprintf(`<%sResponse><requestId>x</requestId></%sResponse>`, action, action))
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func amiFullImageXML() string {
	return amiImageItem("ami-full",
		`<architecture>x86_64</architecture>`+
			`<creationDate>2024-01-15T10:30:00.000Z</creationDate>`+
			`<deprecationTime>2025-06-01T00:00:00.000Z</deprecationTime>`+
			`<description>`+adversarialAMIDescription+`</description>`+
			`<imageOwnerAlias>amazon</imageOwnerAlias>`+
			`<name>`+adversarialAMIName+`</name>`+
			`<platformDetails>Linux/UNIX</platformDetails>`+
			`<rootDeviceType>ebs</rootDeviceType>`)
}

func amiSparseImageXML() string {
	return amiImageItem("ami-sparse",
		`<architecture>arm64</architecture>`+
			`<creationDate>not-a-timestamp</creationDate>`+
			`<platform>Windows</platform>`)
}

func findAMIRecord(records []collector.Record, amiID string) *collector.Record {
	for i := range records {
		row := &records[i]
		if row.Resource != nil && row.Resource.ResourceType == awsv1.ResourceTypeEC2AMI && row.Resource.ResourceID == amiID {
			return row
		}
	}
	return nil
}

func findDenialEffect(err error, effect string) bool {
	denied, ok := err.(*optionalReadDenied)
	if !ok {
		return false
	}
	for _, entry := range denied.denials {
		if entry.effect == effect {
			return true
		}
	}
	return false
}

func TestAMIDetailsEnrichResolvedAMIs(t *testing.T) {
	instances := amiInstancesXML(
		`<item><instanceId>i-1</instanceId><imageId>ami-full</imageId></item>` +
			`<item><instanceId>i-2</instanceId><imageId>ami-sparse</imageId></item>`)
	fixture := newAMITestServer(t, instances, map[string]string{
		"ami-full":   amiFullImageXML(),
		"ami-sparse": amiSparseImageXML(),
	}, "")
	records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatalf("listEC2 = %v", err)
	}
	if fixture.calls["DescribeImages"] != 1 {
		t.Fatalf("DescribeImages calls = %d, want 1", fixture.calls["DescribeImages"])
	}
	if got := fixture.describeQuery.Get("ImageId.1"); got == "" {
		t.Fatalf("DescribeImages sent no image IDs: %v", fixture.describeQuery)
	}
	if got := fixture.describeQuery.Get("IncludeDeprecated"); got != "true" {
		t.Fatalf("IncludeDeprecated = %q, want true so deprecated AMIs do not read back as unresolved", got)
	}
	full := findAMIRecord(records, "ami-full")
	if full == nil {
		t.Fatal("ami-full record missing")
	}
	if !full.TypedOnly {
		t.Fatalf("ami-full record must stay out of transitional record facts")
	}
	if full.Resource.Name != "ami-full" {
		t.Fatalf("AMI resource name = %q, want bare AMI id (never the image Name)", full.Resource.Name)
	}
	wantFull := map[string]any{
		"platform_details": "Linux/UNIX",
		"architecture":     "x86_64",
		"creation_date":    "2024-01-15T10:30:00.000Z",
		"deprecation_time": "2025-06-01T00:00:00.000Z",
		"owner_alias":      "amazon",
		"root_device_type": "ebs",
	}
	if len(full.Resource.Attributes) != len(wantFull) {
		t.Fatalf("ami-full attributes = %#v, want exactly %d typed keys", full.Resource.Attributes, len(wantFull))
	}
	for key, want := range wantFull {
		if full.Resource.Attributes[key] != want {
			t.Fatalf("ami-full attribute %q = %#v, want %q (all = %#v)", key, full.Resource.Attributes[key], want, full.Resource.Attributes)
		}
	}
	sparse := findAMIRecord(records, "ami-sparse")
	if sparse == nil {
		t.Fatal("ami-sparse record missing")
	}
	wantSparse := map[string]any{"architecture": "arm64", "platform": "Windows"}
	if len(sparse.Resource.Attributes) != len(wantSparse) {
		t.Fatalf("ami-sparse attributes = %#v, want only valid fields (blank omitted, unparseable timestamp dropped)", sparse.Resource.Attributes)
	}
	for key, want := range wantSparse {
		if sparse.Resource.Attributes[key] != want {
			t.Fatalf("ami-sparse attribute %q = %#v, want %q", key, sparse.Resource.Attributes[key], want)
		}
	}
}

func TestAMIDetailsDedupesPerScan(t *testing.T) {
	instances := amiInstancesXML(
		`<item><instanceId>i-1</instanceId><imageId>ami-shared</imageId></item>` +
			`<item><instanceId>i-2</instanceId><imageId>ami-shared</imageId></item>` +
			`<item><instanceId>i-3</instanceId><imageId>ami-shared</imageId></item>`)
	fixture := newAMITestServer(t, instances, map[string]string{"ami-shared": amiImageItem("ami-shared", `<architecture>x86_64</architecture>`)}, "")
	records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatalf("listEC2 = %v", err)
	}
	if fixture.calls["DescribeImages"] != 1 {
		t.Fatalf("DescribeImages calls = %d, want 1 for three instances on one AMI", fixture.calls["DescribeImages"])
	}
	count := 0
	for i := range records {
		if row := &records[i]; row.Resource != nil && row.Resource.ResourceType == awsv1.ResourceTypeEC2AMI {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("AMI records = %d, want 1 deduplicated", count)
	}
}

func TestAMIDetailsUnresolvedAMIWarns(t *testing.T) {
	instances := amiInstancesXML(`<item><instanceId>i-1</instanceId><imageId>ami-gone</imageId></item>`)
	fixture := newAMITestServer(t, instances, map[string]string{}, "")
	records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if !findDenialEffect(err, "ami-image-unresolved") {
		t.Fatalf("err = %v, want optional denial with ami-image-unresolved effect", err)
	}
	denied, ok := err.(*optionalReadDenied)
	if !ok {
		t.Fatalf("err = %T: %v", err, err)
	}
	if len(denied.denials) != 1 || denied.denials[0].operation != "DescribeImages" {
		t.Fatalf("denials = %#v, want one DescribeImages entry", denied.denials)
	}
	row := findAMIRecord(records, "ami-gone")
	if row == nil {
		t.Fatal("unresolved AMI identity record lost")
	}
	if len(row.Resource.Attributes) != 0 {
		t.Fatalf("unresolved AMI attributes = %#v, want none", row.Resource.Attributes)
	}
}

func TestAMIDetailsDeniedDegrades(t *testing.T) {
	instances := amiInstancesXML(
		`<item><instanceId>i-1</instanceId><imageId>ami-full</imageId></item>`)
	t.Run("denied", func(t *testing.T) {
		fixture := newAMITestServer(t, instances, map[string]string{}, "UnauthorizedOperation")
		records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
		if !findDenialEffect(err, "ami-details-unavailable") {
			t.Fatalf("err = %v, want optional denial with ami-details-unavailable effect", err)
		}
		kept := map[string]bool{}
		for i := range records {
			if row := &records[i]; row.Resource != nil {
				kept[row.Resource.ResourceID] = true
			}
		}
		if !kept["i-1"] || !kept["ami-full"] {
			t.Fatalf("core inventory lost on denied DescribeImages: %v", kept)
		}
	})
	t.Run("transport stays fatal", func(t *testing.T) {
		fixture := newAMITestServer(t, instances, map[string]string{}, "Throttling")
		records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
		if err == nil || len(records) != 0 {
			t.Fatalf("records=%d err=%v, want fatal transport failure", len(records), err)
		}
		if _, ok := err.(*optionalReadDenied); ok {
			t.Fatalf("throttling classified as optional denial: %v", err)
		}
	})
}

func TestAMIDenialsCombineWithRuleDenial(t *testing.T) {
	instances := amiInstancesXML(`<item><instanceId>i-1</instanceId><imageId>ami-full</imageId></item>`)
	calls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		action := r.Form.Get("Action")
		calls[action]++
		w.Header().Set("Content-Type", "text/xml")
		serve := func(body string) {
			if _, err := w.Write([]byte(body)); err != nil {
				t.Error(err)
			}
		}
		if action == "DescribeSecurityGroupRules" || action == "DescribeImages" {
			w.WriteHeader(http.StatusForbidden)
			serve(`<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>denied</Message></Error></Errors><RequestID>x</RequestID></Response>`)
			return
		}
		if action == "DescribeInstances" {
			serve(instances)
			return
		}
		serve(fmt.Sprintf(`<%sResponse><requestId>x</requestId></%sResponse>`, action, action))
	}))
	defer server.Close()
	records, err := listEC2(context.Background(), amiTestConfig(server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	denied, ok := err.(*optionalReadDenied)
	if !ok || len(denied.denials) != 2 {
		t.Fatalf("err = %v, want two combined optional denials", err)
	}
	if !findDenialEffect(err, "security-group-rules-unavailable") || !findDenialEffect(err, "ami-details-unavailable") {
		t.Fatalf("denials = %#v, want rules + images effects", denied.denials)
	}
	kept := false
	for i := range records {
		if row := &records[i]; row.Resource != nil && row.Resource.ResourceID == "i-1" {
			kept = true
		}
	}
	if !kept {
		t.Fatal("core instance record lost with two denials")
	}
}

func TestAMIDetailsCapTruncates(t *testing.T) {
	var instances strings.Builder
	images := map[string]string{}
	for i := 0; i <= maxAMIImagesPerScan; i++ {
		id := fmt.Sprintf("ami-cap-%03d", i)
		instances.WriteString(`<item><instanceId>i-` + fmt.Sprint(i) + `</instanceId><imageId>` + id + `</imageId></item>`)
		images[id] = amiImageItem(id, `<architecture>x86_64</architecture>`)
	}
	fixture := newAMITestServer(t, amiInstancesXML(instances.String()), images, "")
	records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if fixture.calls["DescribeImages"] != 1 {
		t.Fatalf("DescribeImages calls = %d, want 1 bounded call", fixture.calls["DescribeImages"])
	}
	if fixture.describeQuery.Get("ImageId.100") == "" || fixture.describeQuery.Get("ImageId.101") != "" {
		t.Fatalf("bounded call sent wrong ID count: %d params", len(fixture.describeQuery))
	}
	denied, ok := err.(*optionalReadDenied)
	if !ok || len(denied.denials) != 1 || denied.denials[0].effect != "ami-details-cap-truncated" {
		t.Fatalf("err = %v, want one ami-details-cap-truncated denial", err)
	}
	if denied.denials[0].operation != "DescribeImages" {
		t.Fatalf("cap denial operation = %q", denied.denials[0].operation)
	}
	enriched, bare := 0, 0
	for i := range records {
		row := &records[i]
		if row.Resource == nil || row.Resource.ResourceType != awsv1.ResourceTypeEC2AMI {
			continue
		}
		if len(row.Resource.Attributes) == 0 {
			bare++
			if row.Resource.ResourceID != "ami-cap-100" {
				t.Fatalf("truncated AMI = %q, want deterministic ami-cap-100", row.Resource.ResourceID)
			}
			continue
		}
		enriched++
	}
	if enriched != maxAMIImagesPerScan || bare != 1 {
		t.Fatalf("enriched=%d bare=%d, want %d + 1", enriched, bare, maxAMIImagesPerScan)
	}
}

func TestAMIDetailsInputToPayloadGolden(t *testing.T) {
	instances := amiInstancesXML(`<item><instanceId>i-1</instanceId><imageId>ami-0abc123</imageId></item>`)
	fixture := newAMITestServer(t, instances, map[string]string{
		"ami-0abc123": amiImageItem("ami-0abc123",
			`<architecture>x86_64</architecture>`+
				`<creationDate>2024-01-15T10:30:00.000Z</creationDate>`+
				`<platformDetails>Linux/UNIX</platformDetails>`+
				`<imageOwnerAlias>amazon</imageOwnerAlias>`+
				`<rootDeviceType>ebs</rootDeviceType>`),
	}, "")
	records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatalf("listEC2 = %v", err)
	}
	row := findAMIRecord(records, "ami-0abc123")
	if row == nil {
		t.Fatal("ami-0abc123 record missing")
	}
	observedAt := "2026-10-29T00:00:00Z"
	parsedAt, parseErr := time.Parse(time.RFC3339, observedAt)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	fact, factErr := collector.NewResourceFact(collector.ResourceObservation{
		Boundary: collector.Boundary{
			AccountID: "123456789012", Region: "us-east-1", ServiceKind: "ec2",
			ScopeID: "component:aws-cloud-primary", GenerationID: "generation-1",
			CollectorInstanceID: "aws-cloud-primary", FencingToken: 7, ObservedAt: parsedAt,
		},
		ResourceID: "ami-0abc123", ResourceType: awsv1.ResourceTypeEC2AMI, Name: row.Resource.Name,
		Attributes: row.Resource.Attributes, SourceURI: "aws://123456789012/us-east-1",
	})
	if factErr != nil {
		t.Fatalf("NewResourceFact = %v", factErr)
	}
	if fact.Kind != "aws_resource" || fact.SchemaVersion != "1.0.0" {
		t.Fatalf("fact identity = %q %q", fact.Kind, fact.SchemaVersion)
	}
	if fact.SourceRef.RecordID != "ami-0abc123" || row.Resource.Name != "ami-0abc123" {
		t.Fatalf("AMI identity drifted: record=%q name=%q", fact.SourceRef.RecordID, row.Resource.Name)
	}
	attrs, ok := fact.Payload["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("payload attributes = %#v", fact.Payload["attributes"])
	}
	wantAttrs := map[string]any{
		"platform_details": "Linux/UNIX",
		"architecture":     "x86_64",
		"creation_date":    "2024-01-15T10:30:00.000Z",
		"owner_alias":      "amazon",
		"root_device_type": "ebs",
	}
	encodedWant, err := json.Marshal(wantAttrs)
	if err != nil {
		t.Fatal(err)
	}
	encodedGot, err := json.Marshal(attrs)
	if err != nil {
		t.Fatal(err)
	}
	if string(encodedWant) != string(encodedGot) {
		t.Fatalf("payload attributes = %s, want %s", encodedGot, encodedWant)
	}
	// The stable key derives only from the documented identity recipe, computed
	// here independently of the fact builder.
	identity := map[string]any{"fact_type": "aws_resource", "identity": map[string]any{
		"account_id": "123456789012", "region": "us-east-1",
		"resource_id": "ami-0abc123", "resource_type": "aws_ec2_ami",
	}}
	raw, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if fact.StableKey != hex.EncodeToString(sum[:]) {
		t.Fatalf("stable key = %q, want independently derived %q", fact.StableKey, hex.EncodeToString(sum[:]))
	}
}

// TestAMINameDescriptionNeverSurface is the #9525 exclusion proof: adversarial
// creator-controlled name/description values must not reach producer emission
// in any key or value, benign or secret-shaped.
func TestAMINameDescriptionNeverSurface(t *testing.T) {
	instances := amiInstancesXML(`<item><instanceId>i-1</instanceId><imageId>ami-full</imageId></item>`)
	fixture := newAMITestServer(t, instances, map[string]string{"ami-full": amiFullImageXML()}, "")
	records, err := listEC2(context.Background(), amiTestConfig(fixture.server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if err != nil {
		t.Fatalf("listEC2 = %v", err)
	}
	row := findAMIRecord(records, "ami-full")
	if row == nil {
		t.Fatal("ami-full record missing")
	}
	secrets := []string{"AKIAIOSFODNN7EXAMPLE", "hunter2", "jdoe@corp.example"}
	scanJSON := func(value any) string {
		encoded, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return string(encoded)
	}
	for _, key := range []string{"name", "description"} {
		if _, present := row.Resource.Attributes[key]; present {
			t.Fatalf("AMI attributes admit %q", key)
		}
	}
	emitted := scanJSON(row) + scanJSON(row.Resource.Attributes)
	for _, secret := range secrets {
		if strings.Contains(emitted, secret) {
			t.Fatalf("emitted record contains %q: %s", secret, emitted)
		}
	}
}
