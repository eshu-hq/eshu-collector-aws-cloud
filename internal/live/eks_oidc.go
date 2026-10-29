// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

type eksIAMProvider struct {
	arn, issuer            string
	clientIDs, thumbprints []string
}

// eksOIDCReader caches IAM provider metadata only within one verified EKS
// service-region read. No account or credential state survives the claim.
type eksOIDCReader struct {
	cfg       aws.Config
	loaded    bool
	denial    *optionalReadDenied
	providers []eksIAMProvider
}

func (r *eksOIDCReader) load(ctx context.Context, identity VerifiedIdentity) error {
	if r.loaded {
		return nil
	}
	r.loaded = true
	client := awsiam.NewFromConfig(r.cfg)
	listed, err := client.ListOpenIDConnectProviders(ctx, &awsiam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		if isEKSOIDCListDenial(err) {
			r.denial = &optionalReadDenied{denials: []optionalDenial{{
				operation: "ListOpenIDConnectProviders",
				resource:  "region:" + r.cfg.Region,
				effect:    "eks-oidc-provider-enrichment-unavailable",
			}}}
			return nil
		}
		return fmt.Errorf("list IAM OIDC providers: %w", err)
	}
	if listed == nil {
		return nil
	}
	accountPrefix := "arn:" + identity.Partition + ":iam::" + identity.AccountID + ":oidc-provider/"
	for _, entry := range listed.OpenIDConnectProviderList {
		arn := strings.TrimSpace(aws.ToString(entry.Arn))
		if arn == "" {
			continue
		}
		if !strings.HasPrefix(arn, accountPrefix) {
			return fmt.Errorf("IAM OIDC provider ARN falls outside verified account")
		}
		detail, err := client.GetOpenIDConnectProvider(ctx, &awsiam.GetOpenIDConnectProviderInput{OpenIDConnectProviderArn: aws.String(arn)})
		if err != nil {
			return fmt.Errorf("get IAM OIDC provider: %w", err)
		}
		provider := eksIAMProvider{arn: arn, issuer: strings.TrimPrefix(arn, accountPrefix)}
		if detail != nil {
			if url := strings.TrimSpace(aws.ToString(detail.Url)); url != "" {
				provider.issuer = url
			}
			provider.clientIDs = append([]string(nil), detail.ClientIDList...)
			provider.thumbprints = append([]string(nil), detail.ThumbprintList...)
		}
		r.providers = append(r.providers, provider)
	}
	return nil
}

// enrich attaches IAM evidence only when its issuer matches the EKS-reported
// issuer. A denied list leaves the EKS issuer and core cluster facts intact.
func (r *eksOIDCReader) enrich(ctx context.Context, row *collector.Record, cluster ekstypes.Cluster, identity VerifiedIdentity) (*collector.Record, error) {
	issuer := ""
	if cluster.Identity != nil && cluster.Identity.Oidc != nil {
		issuer = strings.TrimSpace(aws.ToString(cluster.Identity.Oidc.Issuer))
	}
	if issuer == "" {
		return nil, nil
	}
	if err := r.load(ctx, identity); err != nil {
		return nil, err
	}
	if r.denial != nil {
		return eksOIDCProviderRow(row, issuer, eksIAMProvider{}), nil
	}
	for _, provider := range r.providers {
		if normalizeEKSOIDCIssuer(provider.issuer) != normalizeEKSOIDCIssuer(issuer) &&
			normalizeEKSOIDCIssuer(strings.TrimPrefix(provider.arn, "arn:"+identity.Partition+":iam::"+identity.AccountID+":oidc-provider/")) != normalizeEKSOIDCIssuer(issuer) {
			continue
		}
		return eksOIDCProviderRow(row, issuer, provider), nil
	}
	return eksOIDCProviderRow(row, issuer, eksIAMProvider{}), nil
}

// eksOIDCProviderRow retains the EKS-reported issuer even when IAM has no
// matching provider evidence. An IAM ARN is asserted only after a match.
func eksOIDCProviderRow(cluster *collector.Record, issuer string, provider eksIAMProvider) *collector.Record {
	providerID := provider.arn
	if providerID == "" {
		providerID = issuer
	}
	cluster.Resource.Attributes["oidc_provider"] = map[string]any{
		"arn": provider.arn, "client_ids": append([]string(nil), provider.clientIDs...),
		"issuer_url": issuer, "thumbprints": append([]string(nil), provider.thumbprints...),
	}
	resource := collector.LiveResource{
		Region: cluster.Resource.Region, ServiceKind: "eks", ResourceType: "aws_eks_oidc_provider",
		ResourceID: providerID, ARN: provider.arn, Name: issuer,
		Attributes: map[string]any{
			"cluster_arn": cluster.Resource.ARN, "cluster_name": cluster.Resource.Name,
			"client_ids": append([]string(nil), provider.clientIDs...),
			"issuer_url": issuer, "thumbprints": append([]string(nil), provider.thumbprints...),
		},
		CorrelationAnchors: []string{providerID, issuer, cluster.Resource.Name}, SourceRecordID: providerID,
	}
	cluster.Relationships = append(cluster.Relationships, collector.LiveRelationship{
		Region: cluster.Resource.Region, ServiceKind: "eks", RelationshipType: "eks_cluster_has_oidc_provider",
		SourceResourceID: cluster.Resource.ResourceID, SourceARN: cluster.Resource.ARN,
		TargetResourceID: providerID, TargetARN: provider.arn, TargetType: resource.ResourceType,
		Attributes:     map[string]any{"issuer_url": issuer},
		SourceRecordID: cluster.Resource.ResourceID + "#oidc-provider#" + providerID,
	})
	row := record(providerID, "eks", cluster.Resource.Region, issuer, "oidc-provider")
	row.Resource = &resource
	return &row
}

func normalizeEKSOIDCIssuer(issuer string) string {
	issuer = strings.TrimSpace(issuer)
	issuer = strings.TrimPrefix(issuer, "https://")
	issuer = strings.TrimPrefix(issuer, "http://")
	return strings.Trim(issuer, "/")
}

func isEKSOIDCListDenial(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "AccessDenied", "AccessDeniedException":
		return true
	default:
		return false
	}
}
