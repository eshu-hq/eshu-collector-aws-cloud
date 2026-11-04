module github.com/eshu-hq/eshu-collector-aws-cloud

go 1.26.10

require (
	github.com/aws/aws-sdk-go-v2 v1.47.5
	github.com/aws/aws-sdk-go-v2/config v1.33.13
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.52.5
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.46.5
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.75.2
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.91.0
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.72.3
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.343.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.67.2
	github.com/aws/aws-sdk-go-v2/service/ecs v1.103.1
	github.com/aws/aws-sdk-go-v2/service/eks v1.105.2
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.63.6
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.55.7
	github.com/aws/aws-sdk-go-v2/service/iam v1.64.6
	github.com/aws/aws-sdk-go-v2/service/lambda v1.114.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.131.2
	github.com/aws/aws-sdk-go-v2/service/route53 v1.70.6
	github.com/aws/aws-sdk-go-v2/service/s3 v1.114.6
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.50.8
	github.com/aws/aws-sdk-go-v2/service/sns v1.47.7
	github.com/aws/aws-sdk-go-v2/service/sqs v1.52.8
	github.com/aws/aws-sdk-go-v2/service/ssm v1.81.2
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.6
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/aws/aws-sdk-go-v2/service/kms v1.62.2

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.25 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.13
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.39.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.44.1 // indirect
	github.com/aws/smithy-go v1.28.7
	github.com/eshu-hq/eshu-sdk/collector v0.2.0-rc.2
	github.com/eshu-hq/eshu-sdk/factschema v0.1.0-rc.12
)
