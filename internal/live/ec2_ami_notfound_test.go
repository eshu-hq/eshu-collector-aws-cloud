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
)

// TestAMIDetailsNotFoundIDIsolatesSurvivors pins the InvalidAMIID degradation
// contract: a stale AMI id fails the batched DescribeImages call with
// InvalidAMIID.NotFound, the scan isolates it per id, stamps the survivors,
// and warns once with the unresolved count. Core inventory is kept.
func TestAMIDetailsNotFoundIDIsolatesSurvivors(t *testing.T) {
	instances := amiInstancesXML(
		`<item><instanceId>i-good</instanceId><imageId>ami-good</imageId></item>` +
			`<item><instanceId>i-stale</instanceId><imageId>ami-stale</imageId></item>`)
	images := map[string]string{
		"ami-good": amiImageItem("ami-good",
			`<architecture>x86_64</architecture>`+
				`<platformDetails>Linux/UNIX</platformDetails>`),
	}
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		action := r.Form.Get("Action")
		w.Header().Set("Content-Type", "text/xml")
		serve := func(body string) {
			if _, err := w.Write([]byte(body)); err != nil {
				t.Error(err)
			}
		}
		switch action {
		case "DescribeInstances":
			serve(instances)
			return
		case "DescribeImages":
			calls++
			requested := map[string]bool{}
			for key, values := range r.Form {
				if strings.HasPrefix(key, "ImageId.") {
					for _, value := range values {
						requested[value] = true
					}
				}
			}
			// Like AWS, the whole call fails when any requested id is
			// unknown, even when the other ids are resolvable.
			if requested["ami-stale"] {
				w.WriteHeader(http.StatusBadRequest)
				serve(`<Response><Errors><Error><Code>InvalidAMIID.NotFound</Code><Message>not found</Message></Error></Errors><RequestID>x</RequestID></Response>`)
				return
			}
			var set strings.Builder
			for id, item := range images {
				if requested[id] {
					set.WriteString(item)
				}
			}
			serve(fmt.Sprintf(`<DescribeImagesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>x</requestId><imagesSet>%s</imagesSet></DescribeImagesResponse>`, set.String()))
			return
		default:
			serve(fmt.Sprintf(`<%sResponse><requestId>x</requestId></%sResponse>`, action, action))
		}
	}))
	t.Cleanup(server.Close)
	records, err := listEC2(context.Background(), amiTestConfig(server), VerifiedIdentity{AccountID: "123456789012", Partition: "aws"})
	if !findDenialEffect(err, "ami-image-unresolved") {
		t.Fatalf("err = %v, want optional denial with ami-image-unresolved effect, not a fatal scan failure", err)
	}
	denied, ok := err.(*optionalReadDenied)
	if !ok {
		t.Fatalf("err = %T: %v", err, err)
	}
	if len(denied.denials) != 1 || denied.denials[0].operation != "DescribeImages" {
		t.Fatalf("denials = %#v, want one DescribeImages entry", denied.denials)
	}
	if got := denied.denials[0].attributes["unresolved_count"]; got != 1 {
		t.Fatalf("unresolved_count = %#v, want 1 for the stale id", got)
	}
	kept := map[string]bool{}
	for i := range records {
		if row := &records[i]; row.Resource != nil {
			kept[row.Resource.ResourceID] = true
		}
	}
	for _, want := range []string{"i-good", "i-stale", "ami-good", "ami-stale"} {
		if !kept[want] {
			t.Fatalf("core inventory lost on NotFound DescribeImages: kept = %v", kept)
		}
	}
	good := findAMIRecord(records, "ami-good")
	if good == nil {
		t.Fatal("ami-good record missing")
	}
	if good.Resource.Attributes["architecture"] != "x86_64" || good.Resource.Attributes["platform_details"] != "Linux/UNIX" {
		t.Fatalf("ami-good survivor not stamped: %#v", good.Resource.Attributes)
	}
	stale := findAMIRecord(records, "ami-stale")
	if stale == nil {
		t.Fatal("ami-stale identity record missing")
	}
	if len(stale.Resource.Attributes) != 0 {
		t.Fatalf("ami-stale attributes = %#v, want none", stale.Resource.Attributes)
	}
	if calls != 3 {
		t.Fatalf("DescribeImages calls = %d, want 1 batched + 2 isolating singles", calls)
	}
}
