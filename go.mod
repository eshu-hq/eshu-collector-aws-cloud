module github.com/eshu-hq/eshu-collector-aws-cloud

go 1.26.10

require (
	github.com/aws/aws-sdk-go-v2 v1.47.5
	github.com/aws/aws-sdk-go-v2/config v1.33.10
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.52.3
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.46.3
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.75.1
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.90.2
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.72.1
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.341.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.66.6
	github.com/aws/aws-sdk-go-v2/service/ecs v1.102.1
	github.com/aws/aws-sdk-go-v2/service/eks v1.104.3
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.63.5
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.55.5
	github.com/aws/aws-sdk-go-v2/service/iam v1.64.5
	github.com/aws/aws-sdk-go-v2/service/lambda v1.113.3
	github.com/aws/aws-sdk-go-v2/service/rds v1.131.1
	github.com/aws/aws-sdk-go-v2/service/route53 v1.70.5
	github.com/aws/aws-sdk-go-v2/service/s3 v1.114.5
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.50.6
	github.com/aws/aws-sdk-go-v2/service/sns v1.47.6
	github.com/aws/aws-sdk-go-v2/service/sqs v1.52.6
	github.com/aws/aws-sdk-go-v2/service/ssm v1.81.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.5
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/aws/aws-sdk-go-v2/service/kms v1.62.1

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.24 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.10 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.5 // indirect
	github.com/aws/smithy-go v1.28.7
	github.com/eshu-hq/eshu-sdk/collector v0.1.0-rc.4
	github.com/eshu-hq/eshu-sdk/factschema v0.1.0-rc.7
)
