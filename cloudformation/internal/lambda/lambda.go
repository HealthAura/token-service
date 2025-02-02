package lambda

import (
	"github.com/HealthAura/token-service/cloudformation/internal/config"
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsdynamodb"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awskms"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
)

type LambdaStackProps struct {
	TokenTable awsdynamodb.Table
}

type LambdaStack struct {
	stack   awscdk.Stack
	outputs lambdaStackOutputs
}

type lambdaStackOutputs struct {
	TokenService awslambda.Function
}

func NewLambdaStack(scope constructs.Construct, id string, props *LambdaStackProps) *LambdaStack {
	stack := awscdk.NewStack(scope, &id, config.Cfg.StackProps)

	signingKey := awskms.NewKey(stack, jsii.String("TokenSigningKey"), &awskms.KeyProps{
		Description: jsii.String("KMS Key for signing JWT tokens"),
		KeySpec:     awskms.KeySpec_ECC_NIST_P256,
		KeyUsage:    awskms.KeyUsage_SIGN_VERIFY,
	})

	awskms.NewAlias(stack, jsii.String("TokenSigningKeyAlias"), &awskms.AliasProps{
		AliasName: jsii.String("alias/" + string(config.Cfg.Environment) + "-token-signing-key"),
		TargetKey: signingKey,
	})

	lambdaRole := awsiam.NewRole(stack, jsii.String("LambdaExecutionRole"), &awsiam.RoleProps{
		AssumedBy: awsiam.NewServicePrincipal(jsii.String("lambda.amazonaws.com"), nil),
		ManagedPolicies: &[]awsiam.IManagedPolicy{
			awsiam.ManagedPolicy_FromAwsManagedPolicyName(jsii.String("service-role/AWSLambdaVPCAccessExecutionRole")),
		},
	})

	signingKey.Grant(lambdaRole, jsii.String("kms:Sign"))
	signingKey.Grant(lambdaRole, jsii.String("kms:Verify"))
	signingKey.Grant(lambdaRole, jsii.String("kms:GetPublicKey"))
	signingKey.Grant(lambdaRole, jsii.String("kms:DescribeKey"))
	props.TokenTable.GrantFullAccess(lambdaRole)

	lambdaRole.AddToPolicy(awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{
		Actions: jsii.Strings(
			"kms:Sign",
			"kms:Verify",
			"kms:GetPublicKey",
			"kms:DescribeKey",
		),
		Resources: jsii.Strings(*signingKey.KeyArn()),
	}))

	tokenService := awslambda.NewFunction(stack, jsii.String("TokenService"), &awslambda.FunctionProps{
		Runtime:    awslambda.Runtime_PROVIDED_AL2(),
		Handler:    jsii.String("bootstrap"),
		Code:       awslambda.Code_FromBucket(config.Cfg.LambdaBucket, jsii.String(config.Cfg.LambdaCodeS3Key), nil),
		MemorySize: jsii.Number(256),
		Timeout:    awscdk.Duration_Seconds(jsii.Number(30)),
		Tracing:    awslambda.Tracing_ACTIVE,
		Role:       lambdaRole,
		Vpc:        config.Cfg.VPC,
		VpcSubnets: &awsec2.SubnetSelection{
			SubnetType: awsec2.SubnetType_PRIVATE_WITH_EGRESS,
		},
		Environment: &map[string]*string{
			"TOKEN_SERVICE_DYNAMO_TABLE_NAME": props.TokenTable.TableName(),
			"TOKEN_SERVICE_ISSUER":            &config.Cfg.TokenIssuer,
			"TOKEN_SERVICE_SIGNING_KEY_ARN":   signingKey.KeyArn(),
		},
	})

	awscdk.NewCfnOutput(stack, jsii.String("TokenServiceSigningKeyARN"), &awscdk.CfnOutputProps{
		Value:      signingKey.KeyArn(),
		ExportName: jsii.String("healthaura-" + string(config.Cfg.Environment) + "-TokenServiceSigningKeyARN"),
	})

	return &LambdaStack{
		stack: stack,
		outputs: lambdaStackOutputs{
			TokenService: tokenService,
		},
	}
}

func (l *LambdaStack) TokenService() awslambda.Function {
	return l.outputs.TokenService
}
