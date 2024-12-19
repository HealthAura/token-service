package main

import (
	"context"
	"log"

	"github.com/HealthAura/token-service/internal/server"
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
	if application.Config.Service.IsGRPC {
		server.StartGRPC(application)
	} else {
		server.StartLambda(application, application.Logger)
	}
}
