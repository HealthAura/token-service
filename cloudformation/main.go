package main

import (
	"github.com/HealthAura/token-service/cloudformation/internal/api"
	"github.com/HealthAura/token-service/cloudformation/internal/config"
	"github.com/HealthAura/token-service/cloudformation/internal/dynamo"
	"github.com/HealthAura/token-service/cloudformation/internal/lambda"
	"github.com/aws/aws-cdk-go/awscdk/v2"
)

func main() {
	app := awscdk.NewApp(&awscdk.AppProps{})
	config.LoadConfig(app)

	dynamoStack := dynamo.NewLambdaDynamoDBStack(app, "TokenServiceDynamoDBStack")

	lambdaStack := lambda.NewLambdaStack(app, "TokenServiceLambdaStack", &lambda.LambdaStackProps{
		TokenTable: dynamoStack.TokenTable(),
	})

	api.NewAPIGatewayStack(app, "TokenServiceAPIGatewayStack", &api.APIGatewayStackProps{
		TokenService: lambdaStack.TokenService(),
	})

	app.Synth(nil)
}
