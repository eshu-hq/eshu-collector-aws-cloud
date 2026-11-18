module github.com/eshu-hq/eshu-collector-aws-cloud

go 1.26.11

require (
	github.com/aws/aws-sdk-go-v2 v1.48.0
	github.com/aws/aws-sdk-go-v2/config v1.33.18
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.52.9
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.46.9
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.75.6
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.92.2
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.74.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.347.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.67.6
	github.com/aws/aws-sdk-go-v2/service/ecs v1.105.1
	github.com/aws/aws-sdk-go-v2/service/eks v1.105.6
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.64.0
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.55.11
	github.com/aws/aws-sdk-go-v2/service/iam v1.66.0
	github.com/aws/aws-sdk-go-v2/service/lambda v1.115.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.133.0
	github.com/aws/aws-sdk-go-v2/service/route53 v1.71.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.114.10
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.51.0
	github.com/aws/aws-sdk-go-v2/service/sns v1.48.0
	github.com/aws/aws-sdk-go-v2/service/sqs v1.53.0
	github.com/aws/aws-sdk-go-v2/service/ssm v1.83.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.52.0
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/aws/aws-sdk-go-v2/service/kms v1.62.6

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.27 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.21.0
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.39.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.44.5 // indirect
	github.com/aws/smithy-go v1.28.9
	github.com/eshu-hq/eshu-sdk/collector v0.2.0-rc.4
	github.com/eshu-hq/eshu-sdk/factschema v0.1.0-rc.19
)
