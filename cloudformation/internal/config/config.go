package config

import (
	"log"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awss3"
	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
	"github.com/caarlos0/env/v6"
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
	Account         string      `env:"AWS_ACCOUNT"`
	Environment     Environment `env:"ENVIRONMENT" envDefault:"dev"`
	Region          string      `env:"AWS_REGION" envDefault:"us-east-1"`
	LambdaCodeS3Key string      `env:"LAMBDA_CODE_S3_KEY" envDefault:"deployment.zip"`
	VPCID           string      `env:"VPC_ID"`

	VPC          awsec2.IVpc
	LambdaBucket awss3.IBucket
	StackProps   *awscdk.StackProps
}

var (
	Cfg *Config
)

func LoadConfig(scope constructs.Construct) {
	cfg := Config{}
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load environment: %s", err.Error())
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
		VpcId: jsii.String(cfg.VPCID),
	})

	lambdaBucketARN := awscdk.Fn_ImportValue(jsii.String("healthaura-" + string(cfg.Environment) + "-LambdaFunctionsBucketArn"))
	lambdaBucket := awss3.Bucket_FromBucketArn(stack, jsii.String("LambdaFunctionsS3"), lambdaBucketARN)

	cfg.VPC = vpc
	cfg.LambdaBucket = lambdaBucket
	cfg.StackProps = stackProps
	Cfg = &cfg
}
