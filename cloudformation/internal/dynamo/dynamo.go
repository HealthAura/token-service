package dynamo

import (
	"github.com/HealthAura/token-service/cloudformation/internal/config"
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsdynamodb"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awskms"
	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
)

type LambdaDynamoDBStack struct {
	stack   awscdk.Stack
	outputs lambdaDynamoDBStackOutputs
}

type lambdaDynamoDBStackOutputs struct {
	TokenTable awsdynamodb.Table
}

func NewLambdaDynamoDBStack(scope constructs.Construct, id string) *LambdaDynamoDBStack {
	stack := awscdk.NewStack(scope, &id, config.Cfg.StackProps)

	// Add a DynamoDB Gateway VPC Endpoint
	awsec2.NewGatewayVpcEndpoint(stack, jsii.String("DynamoDBEndpoint"), &awsec2.GatewayVpcEndpointProps{
		Service: awsec2.GatewayVpcEndpointAwsService_DYNAMODB(),
		Vpc:     config.Cfg.VPC,
		Subnets: &[]*awsec2.SubnetSelection{{SubnetType: awsec2.SubnetType_PRIVATE_ISOLATED}},
	})

	// KMS Key for DynamoDB table encryption
	tokenTableKey := awskms.NewKey(stack, jsii.String("TokenTableKey"), &awskms.KeyProps{
		Description:       jsii.String("Customer managed key for token table encryption"),
		EnableKeyRotation: jsii.Bool(true),
		Policy:            createKmsKeyPolicy(),
	})

	// KMS Alias for the key
	awskms.NewAlias(stack, jsii.String("TokenTableKeyAlias"), &awskms.AliasProps{
		AliasName: jsii.String("alias/" + string(config.Cfg.Environment) + "-token-table-key"),
		TargetKey: tokenTableKey,
	})

	// DynamoDB Table
	tokenTable := awsdynamodb.NewTable(stack, jsii.String("TokenTable"), &awsdynamodb.TableProps{
		TableName:           jsii.String(string(config.Cfg.Environment) + "-tokens"),
		BillingMode:         awsdynamodb.BillingMode_PAY_PER_REQUEST,
		PartitionKey:        &awsdynamodb.Attribute{Name: jsii.String("signature_hash"), Type: awsdynamodb.AttributeType_STRING},
		PointInTimeRecovery: jsii.Bool(true),
		Encryption:          awsdynamodb.TableEncryption_CUSTOMER_MANAGED,
		EncryptionKey:       tokenTableKey,
	})

	return &LambdaDynamoDBStack{
		stack: stack,
		outputs: lambdaDynamoDBStackOutputs{
			TokenTable: tokenTable,
		},
	}
}

func createKmsKeyPolicy() awsiam.PolicyDocument {
	return awsiam.NewPolicyDocument(&awsiam.PolicyDocumentProps{
		Statements: &[]awsiam.PolicyStatement{
			awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{
				Sid:        jsii.String("EnableIAMUserPermissions"),
				Effect:     awsiam.Effect_ALLOW,
				Actions:    jsii.Strings("kms:*"),
				Principals: &[]awsiam.IPrincipal{awsiam.NewAccountRootPrincipal()},
				Resources:  jsii.Strings("*"),
			}),
			awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{
				Sid:    jsii.String("AllowDynamoDBToUseKey"),
				Effect: awsiam.Effect_ALLOW,
				Actions: jsii.Strings(
					"kms:Encrypt",
					"kms:Decrypt",
					"kms:GenerateDataKey",
				),
				Principals: &[]awsiam.IPrincipal{
					awsiam.NewServicePrincipal(jsii.String("dynamodb.amazonaws.com"), nil),
				},
				Resources: jsii.Strings("*"),
			}),
		},
	})
}

func (l *LambdaDynamoDBStack) TokenTable() awsdynamodb.Table {
	return l.outputs.TokenTable
}
