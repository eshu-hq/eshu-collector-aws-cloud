// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsapigateway "github.com/aws/aws-sdk-go-v2/service/apigateway"
	awsapigatewayv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	awscloudfront "github.com/aws/aws-sdk-go-v2/service/cloudfront"
	awscloudwatchlogs "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	awseventbridge "github.com/aws/aws-sdk-go-v2/service/eventbridge"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awsroute53 "github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	awssns "github.com/aws/aws-sdk-go-v2/service/sns"
	awssqs "github.com/aws/aws-sdk-go-v2/service/sqs"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// listAPIGateway mirrors the in-tree apigateway snapshot: REST APIs, HTTP
// and WebSocket APIs, and custom domain names as metadata-only records.
func listAPIGateway(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	v1 := awsapigateway.NewFromConfig(cfg)
	v2 := awsapigatewayv2.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	rest := awsapigateway.NewGetRestApisPaginator(v1, &awsapigateway.GetRestApisInput{})
	for rest.HasMorePages() {
		page, err := rest.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("apigateway get rest APIs: %w", err)
		}
		for _, api := range page.Items {
			records = append(records, record(aws.ToString(api.Id), "apigateway", region, aws.ToString(api.Name), "rest-api"))
		}
	}
	domains := awsapigateway.NewGetDomainNamesPaginator(v1, &awsapigateway.GetDomainNamesInput{})
	for domains.HasMorePages() {
		page, err := domains.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("apigateway get domain names: %w", err)
		}
		for _, domain := range page.Items {
			records = append(records, record("", "apigateway", region, aws.ToString(domain.DomainName), "domain-name"))
		}
	}
	var nextToken *string
	for {
		page, err := v2.GetApis(ctx, &awsapigatewayv2.GetApisInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("apigatewayv2 get APIs: %w", err)
		}
		for _, api := range page.Items {
			records = append(records, record(aws.ToString(api.ApiId), "apigateway", region, aws.ToString(api.Name), "http-api"))
		}
		if page.NextToken == nil || aws.ToString(page.NextToken) == "" {
			break
		}
		nextToken = page.NextToken
	}
	nextToken = nil
	for {
		page, err := v2.GetDomainNames(ctx, &awsapigatewayv2.GetDomainNamesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("apigatewayv2 get domain names: %w", err)
		}
		for _, domain := range page.Items {
			records = append(records, record(aws.ToString(domain.DomainNameArn), "apigateway", region, aws.ToString(domain.DomainName), "domain-name"))
		}
		if page.NextToken == nil || aws.ToString(page.NextToken) == "" {
			break
		}
		nextToken = page.NextToken
	}
	return records, nil
}

// listCloudFront mirrors the in-tree cloudfront scanner: distribution
// metadata only.
func listCloudFront(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awscloudfront.NewFromConfig(cfg)
	records := []collector.Record{}
	distributions := awscloudfront.NewListDistributionsPaginator(client, &awscloudfront.ListDistributionsInput{})
	for distributions.HasMorePages() {
		page, err := distributions.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("cloudfront list distributions: %w", err)
		}
		if page.DistributionList == nil {
			continue
		}
		for _, distribution := range page.DistributionList.Items {
			row, err := cloudFrontDistributionRecord(distribution)
			if err != nil {
				return nil, err
			}
			records = append(records, row)
		}
	}
	return records, nil
}

// listCloudWatchLogs mirrors the in-tree cloudwatchlogs scanner: log group
// metadata only. Log events, streams, and query results stay unread.
func listCloudWatchLogs(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awscloudwatchlogs.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	groups := awscloudwatchlogs.NewDescribeLogGroupsPaginator(client, &awscloudwatchlogs.DescribeLogGroupsInput{})
	for groups.HasMorePages() {
		page, err := groups.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("cloudwatchlogs describe log groups: %w", err)
		}
		for _, group := range page.LogGroups {
			name := aws.ToString(group.LogGroupName)
			records = append(records, record(aws.ToString(group.Arn), "cloudwatchlogs", region, name, "log-group"))
		}
	}
	return records, nil
}

// listEventBridge mirrors the in-tree eventbridge scanner: buses and their
// rules as metadata-only records. Event payloads stay unread.
func listEventBridge(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awseventbridge.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	var nextToken *string
	for {
		page, err := client.ListEventBuses(ctx, &awseventbridge.ListEventBusesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("eventbridge list event buses: %w", err)
		}
		for _, bus := range page.EventBuses {
			name := aws.ToString(bus.Name)
			records = append(records, record(aws.ToString(bus.Arn), "eventbridge", region, name, "event-bus"))
			var ruleToken *string
			for {
				rules, err := client.ListRules(ctx, &awseventbridge.ListRulesInput{EventBusName: bus.Name, NextToken: ruleToken})
				if err != nil {
					return nil, fmt.Errorf("eventbridge list rules: %w", err)
				}
				for _, rule := range rules.Rules {
					records = append(records, record(aws.ToString(rule.Arn), "eventbridge", region, aws.ToString(rule.Name), "rule"))
				}
				if rules.NextToken == nil || aws.ToString(rules.NextToken) == "" {
					break
				}
				ruleToken = rules.NextToken
			}
		}
		if page.NextToken == nil || aws.ToString(page.NextToken) == "" {
			break
		}
		nextToken = page.NextToken
	}
	return records, nil
}

// listIAM mirrors the in-tree iam scanner's read surface (roles, users,
// customer-managed policies, instance profiles, OIDC providers) as
// metadata-only records. Policy documents stay unread.
func listIAM(ctx context.Context, cfg aws.Config, identity VerifiedIdentity) ([]collector.Record, error) {
	client := awsiam.NewFromConfig(cfg)
	region := cfg.Region
	records, err := listIAMRoleRecords(ctx, client, region, identity)
	if err != nil {
		return nil, err
	}
	userRecords, err := listIAMUserRecords(ctx, client, region, identity)
	if err != nil {
		return nil, err
	}
	records = append(records, userRecords...)
	policies := awsiam.NewListPoliciesPaginator(client, &awsiam.ListPoliciesInput{Scope: iamtypes.PolicyScopeTypeLocal})
	for policies.HasMorePages() {
		page, err := policies.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iam list policies: %w", err)
		}
		for _, policy := range page.Policies {
			records = append(records, record(aws.ToString(policy.Arn), "iam", region, aws.ToString(policy.PolicyName), "policy"))
		}
	}
	profiles := awsiam.NewListInstanceProfilesPaginator(client, &awsiam.ListInstanceProfilesInput{})
	for profiles.HasMorePages() {
		page, err := profiles.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iam list instance profiles: %w", err)
		}
		for _, profile := range page.InstanceProfiles {
			records = append(records, record(aws.ToString(profile.Arn), "iam", region, aws.ToString(profile.InstanceProfileName), "instance-profile"))
		}
	}
	providers, err := client.ListOpenIDConnectProviders(ctx, &awsiam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return nil, fmt.Errorf("iam list OIDC providers: %w", err)
	}
	for _, provider := range providers.OpenIDConnectProviderList {
		arn := aws.ToString(provider.Arn)
		records = append(records, record(arn, "iam", region, lastSegment(arn, "/"), "oidc-provider"))
	}
	return records, nil
}

// listRoute53 mirrors the in-tree route53 scanner: hosted zones and their
// resource record sets. Record values are names and types only.
func listRoute53(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awsroute53.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	zones := awsroute53.NewListHostedZonesPaginator(client, &awsroute53.ListHostedZonesInput{})
	for zones.HasMorePages() {
		page, err := zones.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("route53 list hosted zones: %w", err)
		}
		for _, zone := range page.HostedZones {
			zoneID := aws.ToString(zone.Id)
			records = append(records, record(zoneID, "route53", region, strings.TrimSuffix(aws.ToString(zone.Name), "."), "hosted-zone"))
			var startName, startID *string
			var startType route53types.RRType
			for {
				sets, err := client.ListResourceRecordSets(ctx, &awsroute53.ListResourceRecordSetsInput{
					HostedZoneId:          zone.Id,
					StartRecordName:       startName,
					StartRecordType:       startType,
					StartRecordIdentifier: startID,
				})
				if err != nil {
					return nil, fmt.Errorf("route53 list resource record sets: %w", err)
				}
				for _, set := range sets.ResourceRecordSets {
					records = append(records, record(zoneID+"/"+aws.ToString(set.Name)+"/"+string(set.Type), "route53", region, strings.TrimSuffix(aws.ToString(set.Name), "."), "record-set"))
				}
				if !sets.IsTruncated {
					break
				}
				startName, startID = sets.NextRecordName, sets.NextRecordIdentifier
				if sets.NextRecordType != "" {
					startType = route53types.RRType(sets.NextRecordType)
				}
			}
		}
	}
	return records, nil
}

// listSNS mirrors the in-tree sns scanner: topics and their subscriptions.
// Subscription endpoints (emails, phone numbers, URLs) stay unrecorded:
// only the protocol and the subscription ARN identify a subscription.
func listSNS(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awssns.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	topics := awssns.NewListTopicsPaginator(client, &awssns.ListTopicsInput{})
	for topics.HasMorePages() {
		page, err := topics.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("sns list topics: %w", err)
		}
		for _, topic := range page.Topics {
			arn := aws.ToString(topic.TopicArn)
			records = append(records, record(arn, "sns", region, lastSegment(arn, ":"), "topic"))
			subscriptions := awssns.NewListSubscriptionsByTopicPaginator(client, &awssns.ListSubscriptionsByTopicInput{TopicArn: topic.TopicArn})
			for subscriptions.HasMorePages() {
				subscriptionPage, err := subscriptions.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("sns list subscriptions: %w", err)
				}
				for _, subscription := range subscriptionPage.Subscriptions {
					records = append(records, record(aws.ToString(subscription.SubscriptionArn), "sns", region, aws.ToString(subscription.Protocol), "subscription"))
				}
			}
		}
	}
	return records, nil
}

// listSQS mirrors the in-tree sqs scanner: queue inventory. Message bodies,
// queue policy JSON, and attribute payloads stay unread.
func listSQS(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awssqs.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	queues := awssqs.NewListQueuesPaginator(client, &awssqs.ListQueuesInput{})
	for queues.HasMorePages() {
		page, err := queues.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("sqs list queues: %w", err)
		}
		for _, url := range page.QueueUrls {
			records = append(records, record(url, "sqs", region, lastSegment(url, "/"), "queue"))
		}
	}
	return records, nil
}
