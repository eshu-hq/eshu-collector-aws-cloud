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
	// AssumeRole exchanges ambient credentials for the scope role when
	// Config carries one; nil fails closed on such scopes. Production wires
	// AssumeScopeRole (STS AssumeRole with the scope external ID).
	AssumeRole func(ctx context.Context, base aws.Config, roleARN, externalID string) (aws.Config, error)
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
	S3Postures      []collector.S3BucketPostureObservation
	// SGPostures carries one aws_security_group_rule posture per
	// DescribeSecurityGroupRules row; EC2Postures carries one
	// ec2_instance_posture per DescribeInstances row.
	SGPostures  []collector.SecurityGroupRuleObservation
	EC2Postures []collector.EC2InstancePostureObservation
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
	s3Postures := []collector.S3BucketPostureObservation{}
	sgPostures := []collector.SecurityGroupRuleObservation{}
	ec2Postures := []collector.EC2InstancePostureObservation{}
	warningObservations := []collector.WarningObservation{}
	ordinaryFailure := false
	for i, region := range config.Regions {
		cfg, err := c.loadConfig(ctx, region)
		if err != nil {
			return Outcome{}, fmt.Errorf("live %s: %w", region, err)
		}
		assumed := config.RoleARN != ""
		if assumed {
			if c.AssumeRole == nil {
				return Outcome{}, fmt.Errorf("live %s: scope carries a role but no assume-role implementation is wired", region)
			}
			cfg, err = c.AssumeRole(ctx, cfg, config.RoleARN, config.ExternalID)
			if err != nil {
				return Outcome{}, fmt.Errorf("live %s: assume scope role: %w", region, err)
			}
		}
		cfg.Region = region
		verify := c.VerifyIdentity
		if verify == nil {
			verify = callerIdentity
		}
		identity, err := verify(ctx, cfg)
		if err != nil || identity.AccountID == "" || identity.Partition == "" {
			return Outcome{}, verifyError(region, assumed, config.RoleARN, fmt.Errorf("live AWS account verification failed"))
		}
		if identity.AccountID != config.AccountID {
			return Outcome{}, verifyError(region, assumed, config.RoleARN, fmt.Errorf("live AWS credentials do not match configured account"))
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
							Message:        optionalDenialMessage(entry),
							SourceRecordID: entry.operation + ":" + entry.resource,
							Attributes:     optionalDenialAttributes(entry),
						})
					}
				} else {
					ordinaryFailure = true
					warnings = append(warnings, fmt.Sprintf("%s/%s: %s", service, region, firstLine(err.Error())))
					continue
				}
			}
			for _, item := range listed {
				if item.S3Posture != nil {
					posture := *item.S3Posture
					posture.Boundary.AccountID = config.AccountID
					s3Postures = append(s3Postures, posture)
				}
				if item.SGPosture != nil {
					posture := *item.SGPosture
					posture.Boundary.AccountID = config.AccountID
					sgPostures = append(sgPostures, posture)
				}
				if item.EC2Posture != nil {
					posture := *item.EC2Posture
					posture.Boundary.AccountID = config.AccountID
					ec2Postures = append(ec2Postures, posture)
				}
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
				resources = append(resources, resourceObservation(config.AccountID, item.Resource))
			}
		}
	}
	if len(records) == 0 && len(resources) == 0 && len(warnings) > 0 && (ordinaryFailure || len(warningObservations) == 0) {
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
		S3Postures:          s3Postures,
		SGPostures:          sgPostures,
		EC2Postures:         ec2Postures,
	}, nil
}

// optionalDenial identifies one reviewed API read whose denial leaves the
// enclosing service's other observations usable. Message overrides the
// default denial wording for non-denial degradations (cap truncation,
// unresolved images); attributes carries extra warning attributes such as
// counts, never identities.
type optionalDenial struct {
	operation, resource, effect string
	message                     string
	attributes                  map[string]any
}

// optionalDenialMessage renders the warning message, keeping the exact
// historical denial wording unless the entry overrides it.
func optionalDenialMessage(entry optionalDenial) string {
	if strings.TrimSpace(entry.message) != "" {
		return entry.message
	}
	return entry.operation + " denied for " + entry.resource + "; " + entry.effect
}

// optionalDenialAttributes merges the entry's extra attributes over the
// operation, resource, and effect identity the warning fact requires.
func optionalDenialAttributes(entry optionalDenial) map[string]any {
	attrs := map[string]any{"operation": entry.operation, "resource": entry.resource, "effect": entry.effect}
	for key, value := range entry.attributes {
		attrs[key] = value
	}
	return attrs
}

// combineOptionalDenials merges per-operation optional denials into one
// carrier so a scan keeps every surviving record behind a single warning set.
func combineOptionalDenials(denials ...*optionalReadDenied) error {
	var merged []optionalDenial
	for _, denial := range denials {
		if denial == nil {
			continue
		}
		merged = append(merged, denial.denials...)
	}
	if len(merged) == 0 {
		return nil
	}
	return &optionalReadDenied{denials: merged}
}

// optionalReadDenied carries one or more optional denials beside surviving records.
type optionalReadDenied struct{ denials []optionalDenial }

func (e *optionalReadDenied) Error() string {
	return fmt.Sprintf("%d optional API read(s) denied", len(e.denials))
}

// resourceObservation maps one live resource row into the typed observation
// the envelope seam facts out. CollectReport and chain tests share it so the
// tested mapping is the shipped mapping.
func resourceObservation(accountID string, res *collector.LiveResource) collector.ResourceObservation {
	return collector.ResourceObservation{
		Boundary: collector.Boundary{
			AccountID: accountID, Region: res.Region,
			ServiceKind: res.ServiceKind,
		},
		ARN: res.ARN, ResourceID: res.ResourceID,
		ResourceType: res.ResourceType, Name: res.Name,
		State: res.State, Tags: res.Tags,
		Attributes:         res.Attributes,
		CorrelationAnchors: append([]string(nil), res.CorrelationAnchors...),
		SourceRecordID:     res.SourceRecordID,
	}
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
	case strings.HasPrefix(region, "us-iso-"):
		return "aws-iso"
	case strings.HasPrefix(region, "us-isob-"):
		return "aws-iso-b"
	case strings.HasPrefix(region, "us-isoe-"), strings.HasPrefix(region, "eu-isoe-"):
		return "aws-iso-e"
	case strings.HasPrefix(region, "us-isof-"):
		return "aws-iso-f"
	default:
		return "aws"
	}
}
