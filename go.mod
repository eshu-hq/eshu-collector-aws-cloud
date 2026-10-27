module github.com/eshu-hq/eshu-collector-aws-cloud

go 1.26.5

require (
	github.com/aws/aws-sdk-go-v2 v1.41.7
	github.com/aws/aws-sdk-go-v2/config v1.29.15
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.39.3
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.34.3
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.64.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.73.0
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.42.1
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.300.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.36.3
	github.com/aws/aws-sdk-go-v2/service/ecs v1.36.0
	github.com/aws/aws-sdk-go-v2/service/eks v1.83.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.43.13
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.45.25
	github.com/aws/aws-sdk-go-v2/service/iam v1.36.3
	github.com/aws/aws-sdk-go-v2/service/lambda v1.90.1
	github.com/aws/aws-sdk-go-v2/service/rds v1.118.2
	github.com/aws/aws-sdk-go-v2/service/route53 v1.36.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.97.3
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.41.7
	github.com/aws/aws-sdk-go-v2/service/sns v1.39.17
	github.com/aws/aws-sdk-go-v2/service/sqs v1.42.27
	github.com/aws/aws-sdk-go-v2/service/ssm v1.68.6
	github.com/eshu-hq/eshu/sdk/go/collector v0.2.0
	github.com/eshu-hq/eshu/sdk/go/factschema v0.2.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.10 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.68 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.10.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.30.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.20 // indirect
	github.com/aws/smithy-go v1.25.1 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
)
