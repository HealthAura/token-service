package server

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"go.uber.org/zap"
)

func StartLambda(app *Application, logger *zap.Logger) func(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	adapter := httpadapter.New(app.router)
	lambdaHandler := SetupLambda(app, logger)
	lambda.Start(adapter.ProxyWithContext)
	return lambdaHandler
}

func SetupLambda(app *Application, logger *zap.Logger) func(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	adapter := httpadapter.New(app.router)
	return adapter.ProxyWithContext
}
