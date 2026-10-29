// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	awseks "github.com/aws/aws-sdk-go-v2/service/eks"
	awselbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/smithy-go"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// listEC2 mirrors the in-tree ec2 scanner's read surface (VPCs, subnets,
// security groups and rules, network interfaces, instances, volumes) as
// metadata-only records. Instance user data and volume contents stay unread.
func listEC2(ctx context.Context, cfg aws.Config, identity VerifiedIdentity) ([]collector.Record, error) {
	client := awsec2.NewFromConfig(cfg)
	region := cfg.Region
	if !accountPattern.MatchString(identity.AccountID) || identity.Partition != partitionForRegion(region) {
		return nil, fmt.Errorf("ec2 read requires verified account and region partition")
	}
	records := []collector.Record{}

	vpcs := awsec2.NewDescribeVpcsPaginator(client, &awsec2.DescribeVpcsInput{})
	for vpcs.HasMorePages() {
		page, err := vpcs.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 describe VPCs: %w", err)
		}
		for _, vpc := range page.Vpcs {
			records, err = appendEC2Record(records, vpcRecord(vpc, region))
			if err != nil {
				return nil, err
			}
		}
	}
	subnets := awsec2.NewDescribeSubnetsPaginator(client, &awsec2.DescribeSubnetsInput{})
	for subnets.HasMorePages() {
		page, err := subnets.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 describe subnets: %w", err)
		}
		for _, subnet := range page.Subnets {
			records, err = appendEC2Record(records, subnetRecord(subnet, region))
			if err != nil {
				return nil, err
			}
		}
	}
	groups := awsec2.NewDescribeSecurityGroupsPaginator(client, &awsec2.DescribeSecurityGroupsInput{})
	for groups.HasMorePages() {
		page, err := groups.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 describe security groups: %w", err)
		}
		for _, group := range page.SecurityGroups {
			records, err = appendEC2Record(records, securityGroupRecord(group, region))
			if err != nil {
				return nil, err
			}
		}
	}
	rules := awsec2.NewDescribeSecurityGroupRulesPaginator(client, &awsec2.DescribeSecurityGroupRulesInput{})
	ruleRecords := []collector.Record{}
	var ruleDenial error
	for rules.HasMorePages() {
		page, err := rules.NextPage(ctx)
		if err != nil {
			if isOptionalEC2RuleDenial(err) {
				ruleDenial = &optionalReadDenied{denials: []optionalDenial{{operation: "DescribeSecurityGroupRules", resource: "region:" + region, effect: "security-group-rules-unavailable"}}}
				break
			}
			return nil, fmt.Errorf("ec2 describe security group rules: %w", err)
		}
		for _, rule := range page.SecurityGroupRules {
			row, err := securityGroupRuleRecord(rule, region)
			if err != nil {
				return nil, err
			}
			ruleRecords, err = appendEC2Record(ruleRecords, row)
			if err != nil {
				return nil, err
			}
		}
	}
	if ruleDenial == nil {
		records = append(records, ruleRecords...)
	}
	interfaces := awsec2.NewDescribeNetworkInterfacesPaginator(client, networkInterfaceDescribeInput())
	for interfaces.HasMorePages() {
		page, err := interfaces.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 describe network interfaces: %w", err)
		}
		for _, iface := range page.NetworkInterfaces {
			records, err = appendEC2Record(records, networkInterfaceRecord(iface, region, identity))
			if err != nil {
				return nil, err
			}
		}
	}
	instances := awsec2.NewDescribeInstancesPaginator(client, &awsec2.DescribeInstancesInput{})
	seenAMIIDs := make(map[string]struct{})
	for instances.HasMorePages() {
		page, err := instances.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 describe instances: %w", err)
		}
		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				records, err = appendInstanceRecords(records, instance, region, identity, seenAMIIDs)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	volumes := awsec2.NewDescribeVolumesPaginator(client, &awsec2.DescribeVolumesInput{})
	for volumes.HasMorePages() {
		page, err := volumes.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 describe volumes: %w", err)
		}
		for _, volume := range page.Volumes {
			records, err = appendEC2Record(records, volumeRecord(volume, region, identity))
			if err != nil {
				return nil, err
			}
		}
	}
	return records, ruleDenial
}

// isOptionalEC2RuleDenial recognizes the two EC2 authorization errors for the
// one reviewed optional operation. Other API and transport failures stay fatal.
func isOptionalEC2RuleDenial(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "UnauthorizedOperation", "AccessDenied", "AccessDeniedException":
		return true
	default:
		return false
	}
}

func ec2Name(tags []ec2types.Tag, fallback string) string {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == "Name" && strings.TrimSpace(aws.ToString(tag.Value)) != "" {
			return aws.ToString(tag.Value)
		}
	}
	return fallback
}

// listECR mirrors the in-tree ecr scanner: repositories, image digests, and
// lifecycle-policy metadata. Image contents and policy text are never emitted.
func listECR(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awsecr.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	repositories := awsecr.NewDescribeRepositoriesPaginator(client, &awsecr.DescribeRepositoriesInput{})
	for repositories.HasMorePages() {
		page, err := repositories.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ecr describe repositories: %w", err)
		}
		for _, repository := range page.Repositories {
			tags := []ecrtypes.Tag(nil)
			if arn := strings.TrimSpace(aws.ToString(repository.RepositoryArn)); arn != "" {
				tagResult, tagErr := client.ListTagsForResource(ctx, &awsecr.ListTagsForResourceInput{ResourceArn: aws.String(arn)})
				if tagErr != nil {
					return nil, fmt.Errorf("ecr list repository tags: %w", tagErr)
				}
				if tagResult != nil {
					tags = tagResult.Tags
				}
			}
			records = append(records, ecrRepositoryRecord(repository, tags, region))
			seenImages := make(map[string]struct{})
			images := awsecr.NewDescribeImagesPaginator(client, &awsecr.DescribeImagesInput{
				RepositoryName: repository.RepositoryName,
			})
			for images.HasMorePages() {
				imagePage, err := images.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("ecr describe images: %w", err)
				}
				for _, image := range imagePage.ImageDetails {
					records = appendUniqueECRImageRecords(records, seenImages, aws.ToString(repository.RepositoryArn), aws.ToString(repository.RepositoryName), image, region)
				}
			}
			policy, err := readECRLifecyclePolicy(ctx, client, repository, region)
			if err != nil {
				return nil, err
			}
			if policy != nil {
				records = append(records, *policy)
			}
		}
	}
	return records, nil
}

// listEKS reads clusters, nodegroups, and addons for typed resource observations.
// Reported roles and network placements, plus matched membership, produce edges.
func listEKS(ctx context.Context, cfg aws.Config, identity VerifiedIdentity) ([]collector.Record, error) {
	client := awseks.NewFromConfig(cfg)
	region := cfg.Region
	if !accountPattern.MatchString(identity.AccountID) || identity.Partition != partitionForRegion(region) {
		return nil, fmt.Errorf("eks read requires verified account and region partition")
	}
	providers := eksOIDCReader{cfg: cfg}
	records := []collector.Record{}
	clusters := awseks.NewListClustersPaginator(client, &awseks.ListClustersInput{})
	for clusters.HasMorePages() {
		page, err := clusters.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("eks list clusters: %w", err)
		}
		for _, name := range page.Clusters {
			described, err := client.DescribeCluster(ctx, &awseks.DescribeClusterInput{Name: aws.String(name)})
			if err != nil {
				return nil, fmt.Errorf("eks describe cluster: %w", err)
			}
			var clusterResource *collector.LiveResource
			if described.Cluster != nil {
				row, mapErr := eksClusterRecord(*described.Cluster, region)
				if mapErr != nil {
					return nil, mapErr
				}
				providerRow, err := providers.enrich(ctx, &row, *described.Cluster, identity)
				if err != nil {
					return nil, fmt.Errorf("eks enrich cluster OIDC provider: %w", err)
				}
				clusterResource = row.Resource
				records = append(records, row)
				if providerRow != nil {
					records = append(records, *providerRow)
				}
			}
			nodegroups := awseks.NewListNodegroupsPaginator(client, &awseks.ListNodegroupsInput{ClusterName: aws.String(name)})
			for nodegroups.HasMorePages() {
				nodePage, err := nodegroups.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("eks list nodegroups: %w", err)
				}
				for _, nodegroup := range nodePage.Nodegroups {
					described, err := client.DescribeNodegroup(ctx, &awseks.DescribeNodegroupInput{ClusterName: aws.String(name), NodegroupName: aws.String(nodegroup)})
					if err != nil {
						return nil, fmt.Errorf("eks describe nodegroup: %w", err)
					}
					if described.Nodegroup != nil {
						row, mapErr := eksNodegroupRecord(*described.Nodegroup, region)
						if mapErr != nil {
							return nil, mapErr
						}
						if edge, ok := eksMembershipRelationship(clusterResource, row.Resource, name, aws.ToString(described.Nodegroup.ClusterName)); ok {
							row.Relationships = append(row.Relationships, edge)
						}
						records = append(records, row)
					}
				}
			}
			addons := awseks.NewListAddonsPaginator(client, &awseks.ListAddonsInput{ClusterName: aws.String(name)})
			for addons.HasMorePages() {
				addonPage, err := addons.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("eks list addons: %w", err)
				}
				for _, addon := range addonPage.Addons {
					described, err := client.DescribeAddon(ctx, &awseks.DescribeAddonInput{ClusterName: aws.String(name), AddonName: aws.String(addon)})
					if err != nil {
						return nil, fmt.Errorf("eks describe addon: %w", err)
					}
					if described.Addon != nil {
						row, mapErr := eksAddonRecord(*described.Addon, region)
						if mapErr != nil {
							return nil, mapErr
						}
						if edge, ok := eksMembershipRelationship(clusterResource, row.Resource, name, aws.ToString(described.Addon.ClusterName)); ok {
							row.Relationships = append(row.Relationships, edge)
						}
						records = append(records, row)
					}
				}
			}
		}
	}
	if providers.denial != nil {
		return records, providers.denial
	}
	return records, nil
}

// listELBV2 mirrors the in-tree elbv2 scanner: load balancers, target
// groups, listeners, and rules as metadata-only records.
func listELBV2(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awselbv2.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	balancers := awselbv2.NewDescribeLoadBalancersPaginator(client, &awselbv2.DescribeLoadBalancersInput{})
	for balancers.HasMorePages() {
		page, err := balancers.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("elbv2 describe load balancers: %w", err)
		}
		for _, balancer := range page.LoadBalancers {
			records = append(records, record(aws.ToString(balancer.LoadBalancerArn), "elbv2", region, aws.ToString(balancer.LoadBalancerName), "load-balancer"))
			listeners := awselbv2.NewDescribeListenersPaginator(client, &awselbv2.DescribeListenersInput{
				LoadBalancerArn: balancer.LoadBalancerArn,
			})
			for listeners.HasMorePages() {
				listenerPage, err := listeners.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("elbv2 describe listeners: %w", err)
				}
				for _, listener := range listenerPage.Listeners {
					arn := aws.ToString(listener.ListenerArn)
					records = append(records, record(arn, "elbv2", region, lastSegment(arn, "/"), "listener"))
					rules := awselbv2.NewDescribeRulesPaginator(client, &awselbv2.DescribeRulesInput{
						ListenerArn: listener.ListenerArn,
					})
					for rules.HasMorePages() {
						rulePage, err := rules.NextPage(ctx)
						if err != nil {
							return nil, fmt.Errorf("elbv2 describe rules: %w", err)
						}
						for _, rule := range rulePage.Rules {
							ruleARN := aws.ToString(rule.RuleArn)
							records = append(records, record(ruleARN, "elbv2", region, lastSegment(ruleARN, "/"), "rule"))
						}
					}
				}
			}
		}
	}
	targets := awselbv2.NewDescribeTargetGroupsPaginator(client, &awselbv2.DescribeTargetGroupsInput{})
	for targets.HasMorePages() {
		page, err := targets.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("elbv2 describe target groups: %w", err)
		}
		for _, group := range page.TargetGroups {
			records = append(records, record(aws.ToString(group.TargetGroupArn), "elbv2", region, aws.ToString(group.TargetGroupName), "target-group"))
		}
	}
	return records, nil
}

// listLambda mirrors the in-tree lambda scanner: functions, aliases, and
// event-source mappings. Function code and environment values stay unread.
func listLambda(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awslambda.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	functions := awslambda.NewListFunctionsPaginator(client, &awslambda.ListFunctionsInput{})
	for functions.HasMorePages() {
		page, err := functions.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("lambda list functions: %w", err)
		}
		for _, function := range page.Functions {
			functionRecord, err := lambdaFunctionRecord(function, region)
			if err != nil {
				return nil, fmt.Errorf("lambda function identity: %w", err)
			}
			records = append(records, functionRecord)
			aliases := awslambda.NewListAliasesPaginator(client, &awslambda.ListAliasesInput{FunctionName: aws.String(functionRecord.Resource.ResourceID)})
			for aliases.HasMorePages() {
				aliasPage, err := aliases.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("lambda list aliases: %w", err)
				}
				for _, alias := range aliasPage.Aliases {
					records = append(records, record(aws.ToString(alias.AliasArn), "lambda", region, aws.ToString(alias.Name), "alias"))
				}
			}
			mappings := awslambda.NewListEventSourceMappingsPaginator(client, &awslambda.ListEventSourceMappingsInput{FunctionName: aws.String(functionRecord.Resource.ResourceID)})
			for mappings.HasMorePages() {
				mappingPage, err := mappings.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("lambda list event source mappings: %w", err)
				}
				for _, mapping := range mappingPage.EventSourceMappings {
					records = append(records, record(aws.ToString(mapping.EventSourceArn), "lambda", region, aws.ToString(mapping.UUID), "event-source-mapping"))
				}
			}
		}
	}
	return records, nil
}

// chunks splits values into batches of at most size for the Describe calls
// that cap their input arity.
func chunks(values []string, size int) [][]string {
	var batched [][]string
	for len(values) > 0 {
		if len(values) > size {
			batched = append(batched, values[:size])
			values = values[size:]
		} else {
			batched = append(batched, values)
			break
		}
	}
	return batched
}

func lastSegment(value, separator string) string {
	if i := strings.LastIndex(value, separator); i >= 0 && i+1 < len(value) {
		return value[i+1:]
	}
	return value
}

// networkInterfaceDescribeInput includes AWS-managed interfaces in every EC2 page.
func networkInterfaceDescribeInput() *awsec2.DescribeNetworkInterfacesInput {
	return &awsec2.DescribeNetworkInterfacesInput{
		IncludeManagedResources: aws.Bool(true),
		MaxResults:              aws.Int32(1000),
	}
}
