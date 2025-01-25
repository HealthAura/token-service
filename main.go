package main

import (
	"context"
	"log"

	"github.com/HealthAura/token-service/internal/server"
	"go.uber.org/zap"
)

var (
	application *server.Application
)

func init() {
	var err error
	application, err = server.NewApplication(context.Background())
	if err != nil {
		log.Fatalf("failed to initialize application: %v", err)
	}
}

func main() {
	application.Logger.Info("starting token-service", zap.String("signingKey", application.Config.Service.SigningKeyARN))
	server.StartLambda(application, application.Logger)
}
