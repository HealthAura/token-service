package config

import (
	"log"
	"os"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awss3"
	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
)

const (
	AWSDevelopmentAccount = "713881787612"
	AWSQAAccount          = "713881787612"
	AWSProdAccount        = "713881787612"
	AWSRegion             = "us-east-1"
)

type Environment string

const (
	Dev  Environment = "dev"
	QA   Environment = "qa"
	Prod Environment = "prod"
)

type Config struct {
	Account       string
	Environment   Environment
	VPC           awsec2.IVpc
	LambdaBucket  awss3.IBucket
	LambdaCodeKey string
	StackProps    *awscdk.StackProps
}

var (
	Cfg *Config
)

func LoadConfig(scope constructs.Construct) {
	env := os.Getenv("ENVIRONMENT")
	s3Key := os.Getenv("LAMBDA_CODE_S3_KEY")
	if s3Key == "" {
		s3Key = "deployment.zip"
	}

	var environment Environment
	var account string

	switch env {
	case "dev":
		environment = Dev
		account = AWSDevelopmentAccount
	case "qa":
		environment = QA
		account = AWSQAAccount
	case "prod":
		environment = Prod
		account = AWSProdAccount
	default:
		log.Fatalf("failed to initialize environment: %s", env)
	}

	envVariables := &awscdk.Environment{
		Account: jsii.String(AWSDevelopmentAccount),
		Region:  jsii.String(AWSRegion),
	}

	stackProps := &awscdk.StackProps{
		Env: envVariables,
	}

	stack := awscdk.NewStack(scope, jsii.String("TokenServiceConfigStack"), stackProps)

	vpc := awsec2.Vpc_FromLookup(stack, jsii.String("ImportedVPC"), &awsec2.VpcLookupOptions{
		VpcId: jsii.String("vpc-06157f5d2b53bc3d5"),
	})

	lambdaBucketARN := awscdk.Fn_ImportValue(jsii.String("healthaura-" + string(environment) + "-LambdaFunctionsBucketArn"))
	lambdaBucket := awss3.Bucket_FromBucketArn(stack, jsii.String("LambdaFunctionsS3"), lambdaBucketARN)

	Cfg = &Config{
		Account:       account,
		Environment:   environment,
		VPC:           vpc,
		LambdaBucket:  lambdaBucket,
		LambdaCodeKey: s3Key,
		StackProps:    stackProps,
	}
}
