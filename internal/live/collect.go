// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
	awsv1 "github.com/eshu-hq/eshu-sdk/factschema/aws/v1"
)

// Loader lists one service's resources in one region as report records. It
// receives the region-scoped AWS config and verified caller identity; fakes replace
// the registry entry in tests so collection proves out without a network.
type Loader func(ctx context.Context, cfg aws.Config, identity VerifiedIdentity) ([]collector.Record, error)

// VerifiedIdentity is the account and AWS partition returned by STS for the
// credentials used to read a claim. The partition comes from the caller ARN.
type VerifiedIdentity struct {
	AccountID string
	Partition string
}

// Collector runs one live claim. The zero value is usable: it loads ambient
// AWS config per region and calls the production service loaders, so tests
// drive fakes through LoadConfig and Loaders without touching a network.
type Collector struct {
	// LoadConfig resolves region-scoped AWS config; nil selects the ambient
	// production chain (IRSA, ECS/EKS role, instance profile, environment).
	LoadConfig func(ctx context.Context, region string) (aws.Config, error)
	// VerifyIdentity resolves the active credentials account and partition; nil calls STS.
	VerifyIdentity func(ctx context.Context, cfg aws.Config) (VerifiedIdentity, error)
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
	Report              collector.Report
	Warnings            []string
	WarningObservations []collector.WarningObservation
	// Resources are typed observations retained from successful AWS reads.
	Resources       []collector.ResourceObservation
	Relationships   []collector.RelationshipObservation
	ImageReferences []collector.ImageReferenceObservation
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
	relationships := []collector.RelationshipObservation{}
	imageReferences := []collector.ImageReferenceObservation{}
	warningObservations := []collector.WarningObservation{}
	for i, region := range config.Regions {
		cfg, err := c.loadConfig(ctx, region)
		if err != nil {
			return Outcome{}, fmt.Errorf("live %s: %w", region, err)
		}
		cfg.Region = region
		verify := c.VerifyIdentity
		if verify == nil {
			verify = callerIdentity
		}
		identity, err := verify(ctx, cfg)
		if err != nil || identity.AccountID == "" || identity.Partition == "" {
			return Outcome{}, fmt.Errorf("live AWS account verification failed for region %s", region)
		}
		if identity.AccountID != config.AccountID {
			return Outcome{}, fmt.Errorf("live AWS credentials do not match configured account for region %s", region)
		}
		if identity.Partition != partitionForRegion(region) {
			return Outcome{}, fmt.Errorf("live AWS caller partition does not match configured region %s", region)
		}
		for _, service := range config.Services {
			if i > 0 && globalServices[service] {
				continue
			}
			load, ok := registry[service]
			if !ok {
				return Outcome{}, fmt.Errorf("live service %q has no loader", service)
			}
			listed, err := load(ctx, cfg, identity)
			if err != nil {
				var denied *optionalReadDenied
				if errors.As(err, &denied) && len(denied.denials) > 0 {
					warnings = append(warnings, fmt.Sprintf("%s/%s: %s", service, region, denied.Error()))
					for _, entry := range denied.denials {
						warningObservations = append(warningObservations, collector.WarningObservation{
							Boundary:    collector.Boundary{AccountID: config.AccountID, Region: region, ServiceKind: service},
							WarningKind: "permission_denied", ErrorClass: "permission_denied",
							Message:        entry.operation + " denied for " + entry.resource + "; " + entry.effect,
							SourceRecordID: entry.operation + ":" + entry.resource,
							Attributes:     map[string]any{"operation": entry.operation, "resource": entry.resource, "effect": entry.effect},
						})
					}
				} else {
					warnings = append(warnings, fmt.Sprintf("%s/%s: %s", service, region, firstLine(err.Error())))
					continue
				}
			}
			for _, item := range listed {
				if !item.TypedOnly {
					records = append(records, item)
				}
				if edge := item.Relationship; edge != nil {
					relationships = append(relationships, relationshipObservation(config.AccountID, *edge))
				}
				for _, edge := range item.Relationships {
					relationships = append(relationships, relationshipObservation(config.AccountID, edge))
				}
				if image := item.ImageReference; image != nil {
					imageReferences = append(imageReferences, collector.ImageReferenceObservation{
						Boundary:      collector.Boundary{AccountID: config.AccountID, Region: image.Region, ServiceKind: image.ServiceKind},
						RepositoryARN: image.RepositoryARN, RepositoryName: image.RepositoryName, RegistryID: image.RegistryID,
						ImageDigest: image.ImageDigest, ManifestDigest: image.ManifestDigest, Tag: image.Tag,
						PushedAt: image.PushedAt, ImageSizeInBytes: image.ImageSizeInBytes,
						ManifestMediaType: image.ManifestMediaType, ArtifactMediaType: image.ArtifactMediaType,
					})
				}
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
					SourceRecordID:     item.Resource.SourceRecordID,
				})
			}
		}
	}
	if len(records) == 0 && len(resources) == 0 && len(warnings) > 0 {
		return Outcome{}, fmt.Errorf("live collection read nothing: %s", strings.Join(warnings, "; "))
	}
	return Outcome{
		Report: collector.Report{
			GeneratedAt: c.now(),
			Source:      "aws-live:" + config.AccountID + "/" + strings.Join(config.Regions, ","),
			Records:     records,
		},
		Warnings:            warnings,
		WarningObservations: warningObservations,
		Resources:           resources,
		Relationships:       relationships,
		ImageReferences:     imageReferences,
	}, nil
}

// optionalDenial identifies one reviewed API read whose denial leaves the
// enclosing service's other observations usable.
type optionalDenial struct{ operation, resource, effect string }

// optionalReadDenied carries one or more optional denials beside surviving records.
type optionalReadDenied struct{ denials []optionalDenial }

func (e *optionalReadDenied) Error() string {
	return fmt.Sprintf("%d optional API read(s) denied", len(e.denials))
}

func relationshipObservation(accountID string, edge collector.LiveRelationship) collector.RelationshipObservation {
	return collector.RelationshipObservation{
		Boundary:         collector.Boundary{AccountID: accountID, Region: edge.Region, ServiceKind: edge.ServiceKind},
		RelationshipType: edge.RelationshipType, SourceResourceID: edge.SourceResourceID, SourceARN: edge.SourceARN,
		TargetResourceID: edge.TargetResourceID, TargetARN: edge.TargetARN, TargetType: edge.TargetType,
		SourceRecordID: edge.SourceRecordID, Attributes: edge.Attributes,
	}
}

var ec2ResourceTypes = map[string]string{
	"vpc":                 awsv1.ResourceTypeEC2VPC,
	"subnet":              awsv1.ResourceTypeEC2Subnet,
	"security-group":      awsv1.ResourceTypeEC2SecurityGroup,
	"security-group-rule": awsv1.ResourceTypeEC2SecurityGroupRule,
	"network-interface":   awsv1.ResourceTypeEC2NetworkInterface,
	"instance":            awsv1.ResourceTypeEC2Instance,
	"ami":                 awsv1.ResourceTypeEC2AMI,
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

// callerIdentity verifies the account and partition of the credentials used by service clients.
func callerIdentity(ctx context.Context, cfg aws.Config) (VerifiedIdentity, error) {
	output, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return VerifiedIdentity{}, err
	}
	if output == nil {
		return VerifiedIdentity{}, fmt.Errorf("STS returned no caller identity")
	}
	return identityFromCaller(aws.ToString(output.Account), aws.ToString(output.Arn))
}

func identityFromCaller(accountID, callerARN string) (VerifiedIdentity, error) {
	accountID = strings.TrimSpace(accountID)
	parts := strings.SplitN(strings.TrimSpace(callerARN), ":", 6)
	if !accountPattern.MatchString(accountID) || len(parts) != 6 || parts[0] != "arn" || parts[4] != accountID || parts[1] == "" {
		return VerifiedIdentity{}, fmt.Errorf("STS returned an invalid caller identity")
	}
	return VerifiedIdentity{AccountID: accountID, Partition: parts[1]}, nil
}

func partitionForRegion(region string) string {
	switch {
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	default:
		return "aws"
	}
}
