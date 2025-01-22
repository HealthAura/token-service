package dynamo

import (
	"github.com/HealthAura/token-service/cloudformation/internal/config"
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsdynamodb"
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

	tokenTableKey := awskms.NewKey(stack, jsii.String("TokenTableKey"), &awskms.KeyProps{
		Description:       jsii.String("Customer managed key for token table encryption"),
		EnableKeyRotation: jsii.Bool(true),
		Policy:            createKmsKeyPolicy(),
	})

	awskms.NewAlias(stack, jsii.String("TokenTableKeyAlias"), &awskms.AliasProps{
		AliasName: jsii.String("alias/" + string(config.Cfg.Environment) + "-token-table-key"),
		TargetKey: tokenTableKey,
	})

	tokenTable := awsdynamodb.NewTable(stack, jsii.String("TokenTable"), &awsdynamodb.TableProps{
		TableName:           jsii.String(string(config.Cfg.Environment) + "-tokens"),
		BillingMode:         awsdynamodb.BillingMode_PAY_PER_REQUEST,
		PartitionKey:        &awsdynamodb.Attribute{Name: jsii.String("signature_hash"), Type: awsdynamodb.AttributeType_STRING},
		PointInTimeRecovery: jsii.Bool(true),
		Encryption:          awsdynamodb.TableEncryption_CUSTOMER_MANAGED,
		EncryptionKey:       tokenTableKey,
	})

	awscdk.NewCfnOutput(stack, jsii.String("TokenTableName"), &awscdk.CfnOutputProps{
		Value:      tokenTable.TableName(),
		ExportName: jsii.String(string(config.Cfg.Environment) + "-token-table-name"),
	})

	awscdk.NewCfnOutput(stack, jsii.String("TokenTableArn"), &awscdk.CfnOutputProps{
		Value:      tokenTable.TableArn(),
		ExportName: jsii.String(string(config.Cfg.Environment) + "-token-table-arn"),
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
