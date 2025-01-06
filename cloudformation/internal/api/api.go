package api

import (
	"fmt"
	"strings"

	"github.com/HealthAura/token-service/cloudformation/internal/config"
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsapigateway"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
)

type APIGatewayStackProps struct {
	TokenService awslambda.Function
}

func NewAPIGatewayStack(scope constructs.Construct, id string, props *APIGatewayStackProps) awscdk.Stack {
	stack := awscdk.NewStack(scope, &id, config.Cfg.StackProps)

	api := awsapigateway.NewRestApi(stack, jsii.String("TokenServiceApi"), &awsapigateway.RestApiProps{
		RestApiName: jsii.String("TokenServiceApi"),
		Description: jsii.String("Private REST API for Token Service"),
		EndpointConfiguration: &awsapigateway.EndpointConfiguration{
			Types: &[]awsapigateway.EndpointType{
				awsapigateway.EndpointType_PRIVATE,
			},
		},
		CloudWatchRole:              jsii.Bool(true),
		CloudWatchRoleRemovalPolicy: awscdk.RemovalPolicy_RETAIN,
		Deploy:                      jsii.Bool(true),
		Policy: awsiam.NewPolicyDocument(&awsiam.PolicyDocumentProps{
			Statements: &[]awsiam.PolicyStatement{
				awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{
					Effect: awsiam.Effect_ALLOW,
					Principals: &[]awsiam.IPrincipal{
						awsiam.NewAnyPrincipal(),
					},
					Actions: &[]*string{
						jsii.String("execute-api:Invoke"),
					},
					Resources: &[]*string{
						jsii.String(fmt.Sprintf("arn:aws:execute-api:%s:%s:*/*/*",
							*stack.Region(),
							*stack.Account(),
						)),
					},
				}),
			},
		}),
	})

	// Add a VPC endpoint for private communication
	endpoint := awsec2.NewInterfaceVpcEndpoint(stack, jsii.String("ApiGatewayVpcEndpoint"), &awsec2.InterfaceVpcEndpointProps{
		Vpc:               config.Cfg.VPC,
		Open:              jsii.Bool(true),
		Service:           awsec2.InterfaceVpcEndpointAwsService_APIGATEWAY(),
		PrivateDnsEnabled: jsii.Bool(true), // Enable private DNS

	})

	tokenServiceIntegration := awsapigateway.NewLambdaIntegration(props.TokenService, &awsapigateway.LambdaIntegrationOptions{})

	routes := []struct {
		Path    string
		Method  string
		Summary string
	}{
		{Path: "v1/generate", Method: "POST", Summary: "Generate tokens based on claims and DPoP proof"},
		{Path: "v1/generate-nonce", Method: "POST", Summary: "Generate nonce based on claims"},
		{Path: "v1/refresh", Method: "POST", Summary: "Refresh tokens using refresh token and DPoP proof"},
	}

	resources := make(map[string]awsapigateway.IResource)

	for _, route := range routes {
		pathSegments := strings.Split(route.Path, "/")
		currentResource := api.Root()

		for _, segment := range pathSegments {
			resourceKey := fmt.Sprintf("%s/%s", *currentResource.Path(), segment)
			if existingResource, exists := resources[resourceKey]; exists {
				currentResource = existingResource // Reuse existing resource
			} else {
				newResource := currentResource.AddResource(jsii.String(segment), nil)
				resources[resourceKey] = newResource
				currentResource = newResource
			}
		}

		currentResource.AddMethod(jsii.String(route.Method), tokenServiceIntegration, nil)
	}

	awscdk.NewCfnOutput(stack, jsii.String("TokenServiceApiEndpoint"), &awscdk.CfnOutputProps{
		Value:      api.Url(),
		ExportName: jsii.String("healthaura-" + string(config.Cfg.Environment) + "-TokenServiceApiEndpoint"),
	})

	endpointDns := awscdk.Fn_Select(jsii.Number(0), endpoint.VpcEndpointDnsEntries())
	awscdk.NewCfnOutput(stack, jsii.String("VpcEndpointUrl"), &awscdk.CfnOutputProps{
		Value:      endpointDns,
		ExportName: jsii.String("healthaura-" + string(config.Cfg.Environment) + "-TokenServiceVpcEndpointUrl"),
	})

	return stack
}
