// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// Loader lists one service's resources in one region as report records. It
// receives the region-scoped AWS config the Collector loads; fakes replace
// the registry entry in tests so collection proves out without a network.
type Loader func(ctx context.Context, cfg aws.Config) ([]collector.Record, error)

// Collector runs one live claim. The zero value is usable: it loads ambient
// AWS config per region and calls the production service loaders, so tests
// drive fakes through LoadConfig and Loaders without touching a network.
type Collector struct {
	// LoadConfig resolves region-scoped AWS config; nil selects the ambient
	// production chain (IRSA, ECS/EKS role, instance profile, environment).
	LoadConfig func(ctx context.Context, region string) (aws.Config, error)
	// VerifyAccount resolves the active credentials account; nil calls STS.
	VerifyAccount func(ctx context.Context, cfg aws.Config) (string, error)
	// Loaders overrides the production service registry; nil selects it.
	Loaders map[string]Loader
	// Now supplies the report timestamp; nil selects time.Now.
	Now func() time.Time
}

// Outcome is one live collection pass: the report built from every service
// that answered, plus one warning per service-region pair that failed. A
// non-nil error means nothing was readable and the claim must fail instead
// of emitting an empty report that would retire stale evidence.
type Outcome struct {
	Report   collector.Report
	Warnings []string
	// Resources are typed observations retained from successful AWS reads.
	Resources []collector.ResourceObservation
}

func (c Collector) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c Collector) loadConfig(ctx context.Context, region string) (aws.Config, error) {
	if c.LoadConfig != nil {
		return c.LoadConfig(ctx, region)
	}
	return loadAmbientConfig(ctx, region)
}

func (c Collector) loaders() map[string]Loader {
	if c.Loaders != nil {
		return c.Loaders
	}
	return loaders
}

// CollectReport lists every configured service in every configured region.
// Services fail independently: a failed pair contributes a warning and the
// pass keeps going, so one denied API never wipes the evidence the other
// services returned. When every pair fails the report would be an empty
// success that retires good evidence, so CollectReport errors instead.
func (c Collector) CollectReport(ctx context.Context, config Config) (Outcome, error) {
	registry := c.loaders()
	records := []collector.Record{}
	warnings := []string{}
	resources := []collector.ResourceObservation{}
	for i, region := range config.Regions {
		cfg, err := c.loadConfig(ctx, region)
		if err != nil {
			return Outcome{}, fmt.Errorf("live %s: %w", region, err)
		}
		cfg.Region = region
		verify := c.VerifyAccount
		if verify == nil {
			verify = callerAccount
		}
		account, err := verify(ctx, cfg)
		if err != nil || account == "" {
			return Outcome{}, fmt.Errorf("live AWS account verification failed for region %s", region)
		}
		if account != config.AccountID {
			return Outcome{}, fmt.Errorf("live AWS credentials do not match configured account for region %s", region)
		}
		for _, service := range config.Services {
			if i > 0 && globalServices[service] {
				continue
			}
			load, ok := registry[service]
			if !ok {
				return Outcome{}, fmt.Errorf("live service %q has no loader", service)
			}
			listed, err := load(ctx, cfg)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s/%s: %s", service, region, firstLine(err.Error())))
				continue
			}
			records = append(records, listed...)
			for _, item := range listed {
				if item.Resource == nil {
					continue
				}
				resources = append(resources, collector.ResourceObservation{
					Boundary: collector.Boundary{
						AccountID: config.AccountID, Region: item.Resource.Region,
						ServiceKind: item.Resource.ServiceKind,
					},
					ARN: item.Resource.ARN, ResourceID: item.Resource.ResourceID,
					ResourceType: item.Resource.ResourceType, Name: item.Resource.Name,
					State: item.Resource.State, Tags: item.Resource.Tags,
					Attributes:         item.Resource.Attributes,
					CorrelationAnchors: append([]string(nil), item.Resource.CorrelationAnchors...),
				})
			}
		}
	}
	if len(records) == 0 && len(warnings) > 0 {
		return Outcome{}, fmt.Errorf("live collection read nothing: %s", strings.Join(warnings, "; "))
	}
	return Outcome{
		Report: collector.Report{
			GeneratedAt: c.now(),
			Source:      "aws-live:" + config.AccountID + "/" + strings.Join(config.Regions, ","),
			Records:     records,
		},
		Warnings:  warnings,
		Resources: resources,
	}, nil
}

var ec2ResourceTypes = map[string]string{
	"vpc":                 awsv1.ResourceTypeEC2VPC,
	"subnet":              awsv1.ResourceTypeEC2Subnet,
	"security-group":      awsv1.ResourceTypeEC2SecurityGroup,
	"security-group-rule": awsv1.ResourceTypeEC2SecurityGroupRule,
	"network-interface":   awsv1.ResourceTypeEC2NetworkInterface,
	"instance":            awsv1.ResourceTypeEC2Instance,
	"volume":              awsv1.ResourceTypeEC2Volume,
}

// record builds one metadata-only report record. The ID is the resource ARN
// when the API returns one, else the stable service/region/name triple; the
// detail carries kind and region only, never values, documents, or payloads.
func record(arn, service, region, name, kind string) collector.Record {
	id := strings.TrimSpace(arn)
	if id == "" {
		id = service + "/" + region + "/" + name
	}
	result := collector.Record{
		ID:     id,
		Name:   name,
		Detail: "service=" + service + " region=" + region + " kind=" + kind,
	}
	if service == "ec2" && strings.TrimSpace(arn) != "" {
		if resourceType, ok := ec2ResourceTypes[kind]; ok {
			typedName := id
			if kind == "security-group" {
				typedName = name
			}
			result.Resource = &collector.LiveResource{
				Name:   typedName,
				Region: region, ServiceKind: service,
				ResourceType: resourceType, ResourceID: id,
			}
		}
	}
	return result
}

func firstLine(message string) string {
	if i := strings.IndexByte(message, '\n'); i >= 0 {
		return message[:i]
	}
	return message
}

// callerAccount verifies the account of the actual credentials used by service clients.
func callerAccount(ctx context.Context, cfg aws.Config) (string, error) {
	output, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	if output == nil {
		return "", fmt.Errorf("STS returned no caller identity")
	}
	return aws.ToString(output.Account), nil
}
