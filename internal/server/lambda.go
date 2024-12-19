package server

import (
	"context"
	"encoding/json"

	tokenservice "github.com/HealthAura/token-service/gen/token-service.v1"
	"github.com/HealthAura/token-service/internal/middleware/logging"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

type LambdaHandler struct {
	app *Application
}

func StartLambda(app *Application, logger *zap.Logger) func(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	handler := &LambdaHandler{app: app}
	lambdaHandler := LambdaMiddleware(logger, handler.Handle)
	lambda.Start(lambdaHandler)
	return lambdaHandler
}

func (h *LambdaHandler) Handle(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	switch request.Path {
	case "/token/Generate":
		if request.HTTPMethod != "POST" {
			return events.APIGatewayProxyResponse{
				StatusCode: 405,
				Body:       "Method not allowed",
			}, nil
		}

		var generateReq *tokenservice.GenerateRequest
		if err := json.Unmarshal([]byte(request.Body), &generateReq); err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       "Invalid request body",
			}, nil
		}

		resp, err := h.app.TokenManager.Generate(ctx, generateReq)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 500,
				Body:       "Internal server error",
			}, nil
		}

		v, err := json.Marshal(resp)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 500,
				Body:       "Internal server error",
			}, nil
		}

		return events.APIGatewayProxyResponse{
			StatusCode: 200,
			Body:       string(v),
		}, nil
	case "/token/Refresh":
		if request.HTTPMethod != "POST" {
			return events.APIGatewayProxyResponse{
				StatusCode: 405,
				Body:       "Method not allowed",
			}, nil
		}

		var refreshRequest *tokenservice.RefreshRequest
		if err := json.Unmarshal([]byte(request.Body), refreshRequest); err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       "Invalid request body",
			}, nil
		}

		resp, err := h.app.TokenManager.Refresh(ctx, refreshRequest)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 500,
				Body:       "Internal server error",
			}, nil
		}

		v, err := json.Marshal(resp)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 500,
				Body:       "Internal server error",
			}, nil
		}

		return events.APIGatewayProxyResponse{
			StatusCode: 200,
			Body:       string(v),
		}, nil

	case "/token/GenerateNonce":
		if request.HTTPMethod != "POST" {
			return events.APIGatewayProxyResponse{
				StatusCode: 405,
				Body:       "Method not allowed",
			}, nil
		}

		var generateNonceRequest *tokenservice.GenerateNonceRequest
		if err := json.Unmarshal([]byte(request.Body), &generateNonceRequest); err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 400,
				Body:       "Invalid request body",
			}, nil
		}

		resp, err := h.app.TokenManager.GenerateNonce(ctx, &tokenservice.GenerateNonceRequest{})
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 500,
				Body:       "Internal server error",
			}, nil
		}

		v, err := json.Marshal(resp)
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: 500,
				Body:       "Internal server error",
			}, nil
		}

		return events.APIGatewayProxyResponse{
			StatusCode: 200,
			Body:       string(v),
		}, nil

	default:
		return events.APIGatewayProxyResponse{
			StatusCode: 404,
			Body:       "Not found",
		}, nil
	}
}

func LambdaMiddleware(log *zap.Logger, handler func(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error)) func(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	middleware := logging.New(log)

	return func(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		md := metadata.MD{}
		for key, value := range request.Headers {
			md.Append(key, value)
		}
		ctx = metadata.NewIncomingContext(ctx, md)

		resp, err := middleware.Middleware(ctx, request, nil, func(ctx context.Context, req interface{}) (interface{}, error) {
			return handler(ctx, request)
		})

		if response, ok := resp.(events.APIGatewayProxyResponse); ok {
			return response, err
		}

		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "Internal server error",
		}, err
	}
}
