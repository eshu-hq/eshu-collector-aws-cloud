// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"
	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	awseks "github.com/aws/aws-sdk-go-v2/service/eks"
	awselbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	collector "github.com/eshu-hq/eshu-collector-aws-cloud"
)

// listEC2 mirrors the in-tree ec2 scanner's read surface (VPCs, subnets,
// security groups and rules, network interfaces, instances, volumes) as
// metadata-only records. Instance user data and volume contents stay unread.
func listEC2(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awsec2.NewFromConfig(cfg)
	region := cfg.Region
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
			name := aws.ToString(group.GroupName)
			if name == "" {
				name = aws.ToString(group.GroupId)
			}
			records, err = appendEC2Record(records, record(aws.ToString(group.GroupId), "ec2", region, name, "security-group"))
			if err != nil {
				return nil, err
			}
		}
	}
	rules := awsec2.NewDescribeSecurityGroupRulesPaginator(client, &awsec2.DescribeSecurityGroupRulesInput{})
	for rules.HasMorePages() {
		page, err := rules.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 describe security group rules: %w", err)
		}
		for _, rule := range page.SecurityGroupRules {
			row, err := securityGroupRuleRecord(rule, region)
			if err != nil {
				return nil, err
			}
			records, err = appendEC2Record(records, row)
			if err != nil {
				return nil, err
			}
		}
	}
	interfaces := awsec2.NewDescribeNetworkInterfacesPaginator(client, &awsec2.DescribeNetworkInterfacesInput{})
	for interfaces.HasMorePages() {
		page, err := interfaces.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 describe network interfaces: %w", err)
		}
		for _, iface := range page.NetworkInterfaces {
			records, err = appendEC2Record(records, record(aws.ToString(iface.NetworkInterfaceId), "ec2", region, aws.ToString(iface.NetworkInterfaceId), "network-interface"))
			if err != nil {
				return nil, err
			}
		}
	}
	instances := awsec2.NewDescribeInstancesPaginator(client, &awsec2.DescribeInstancesInput{})
	for instances.HasMorePages() {
		page, err := instances.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 describe instances: %w", err)
		}
		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				records, err = appendEC2Record(records, instanceRecord(instance, region))
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
			records, err = appendEC2Record(records, record(aws.ToString(volume.VolumeId), "ec2", region, ec2Name(volume.Tags, aws.ToString(volume.VolumeId)), "volume"))
			if err != nil {
				return nil, err
			}
		}
	}
	return records, nil
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
// lifecycle-policy presence. Image contents and policy text stay unread.
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
			records = append(records, record(aws.ToString(repository.RepositoryArn), "ecr", region, aws.ToString(repository.RepositoryName), "repository"))
			images := awsecr.NewDescribeImagesPaginator(client, &awsecr.DescribeImagesInput{
				RepositoryName: repository.RepositoryName,
			})
			for images.HasMorePages() {
				imagePage, err := images.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("ecr describe images: %w", err)
				}
				for _, image := range imagePage.ImageDetails {
					digest := aws.ToString(image.ImageDigest)
					tag := digest
					if len(image.ImageTags) > 0 {
						tag = image.ImageTags[0]
					}
					name := aws.ToString(repository.RepositoryName) + ":" + tag
					records = append(records, record(aws.ToString(repository.RepositoryArn)+"@"+digest, "ecr", region, name, "image"))
				}
			}
		}
	}
	return records, nil
}

// listECS mirrors the in-tree ecs scanner: clusters, services, tasks, and
// task-definition ARNs. Task-definition bodies stay undescribed.
func listECS(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awsecs.NewFromConfig(cfg)
	region := cfg.Region
	records := []collector.Record{}
	clusters := awsecs.NewListClustersPaginator(client, &awsecs.ListClustersInput{})
	for clusters.HasMorePages() {
		page, err := clusters.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ecs list clusters: %w", err)
		}
		for _, arn := range page.ClusterArns {
			described, err := client.DescribeClusters(ctx, &awsecs.DescribeClustersInput{Clusters: []string{arn}})
			if err != nil {
				return nil, fmt.Errorf("ecs describe clusters: %w", err)
			}
			for _, cluster := range described.Clusters {
				records = append(records, record(aws.ToString(cluster.ClusterArn), "ecs", region, aws.ToString(cluster.ClusterName), "cluster"))
			}
			services := awsecs.NewListServicesPaginator(client, &awsecs.ListServicesInput{Cluster: aws.String(arn)})
			for services.HasMorePages() {
				servicePage, err := services.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("ecs list services: %w", err)
				}
				for _, chunk := range chunks(servicePage.ServiceArns, 10) {
					described, err := client.DescribeServices(ctx, &awsecs.DescribeServicesInput{Cluster: aws.String(arn), Services: chunk})
					if err != nil {
						return nil, fmt.Errorf("ecs describe services: %w", err)
					}
					for _, service := range described.Services {
						records = append(records, record(aws.ToString(service.ServiceArn), "ecs", region, aws.ToString(service.ServiceName), "service"))
					}
				}
			}
			tasks := awsecs.NewListTasksPaginator(client, &awsecs.ListTasksInput{Cluster: aws.String(arn)})
			for tasks.HasMorePages() {
				taskPage, err := tasks.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("ecs list tasks: %w", err)
				}
				for _, chunk := range chunks(taskPage.TaskArns, 100) {
					described, err := client.DescribeTasks(ctx, &awsecs.DescribeTasksInput{Cluster: aws.String(arn), Tasks: chunk})
					if err != nil {
						return nil, fmt.Errorf("ecs describe tasks: %w", err)
					}
					for _, task := range described.Tasks {
						arn := aws.ToString(task.TaskArn)
						records = append(records, record(arn, "ecs", region, lastSegment(arn, "/"), "task"))
					}
				}
			}
		}
	}
	definitions := awsecs.NewListTaskDefinitionsPaginator(client, &awsecs.ListTaskDefinitionsInput{})
	for definitions.HasMorePages() {
		page, err := definitions.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ecs list task definitions: %w", err)
		}
		for _, arn := range page.TaskDefinitionArns {
			records = append(records, record(arn, "ecs", region, lastSegment(arn, "/"), "task-definition"))
		}
	}
	return records, nil
}

// listEKS mirrors the in-tree eks scanner: clusters, nodegroups, and addons
// as metadata-only records.
func listEKS(ctx context.Context, cfg aws.Config) ([]collector.Record, error) {
	client := awseks.NewFromConfig(cfg)
	region := cfg.Region
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
			if described.Cluster != nil {
				records = append(records, record(aws.ToString(described.Cluster.Arn), "eks", region, aws.ToString(described.Cluster.Name), "cluster"))
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
						records = append(records, record(aws.ToString(described.Nodegroup.NodegroupArn), "eks", region, aws.ToString(described.Nodegroup.NodegroupName), "nodegroup"))
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
						records = append(records, record(aws.ToString(described.Addon.AddonArn), "eks", region, aws.ToString(described.Addon.AddonName), "addon"))
					}
				}
			}
		}
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
			name := aws.ToString(function.FunctionName)
			records = append(records, record(aws.ToString(function.FunctionArn), "lambda", region, name, "function"))
			aliases := awslambda.NewListAliasesPaginator(client, &awslambda.ListAliasesInput{FunctionName: function.FunctionName})
			for aliases.HasMorePages() {
				aliasPage, err := aliases.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("lambda list aliases: %w", err)
				}
				for _, alias := range aliasPage.Aliases {
					records = append(records, record(aws.ToString(alias.AliasArn), "lambda", region, aws.ToString(alias.Name), "alias"))
				}
			}
			mappings := awslambda.NewListEventSourceMappingsPaginator(client, &awslambda.ListEventSourceMappingsInput{FunctionName: function.FunctionName})
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
