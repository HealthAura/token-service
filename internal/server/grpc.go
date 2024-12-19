package server

import (
	"fmt"
	"net"

	tokenservice "github.com/HealthAura/token-service/gen/token-service.v1"
	"github.com/HealthAura/token-service/internal/endpoint"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func StartGRPC(app *Application) error {
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			grpc_ctxtags.UnaryServerInterceptor(grpc_ctxtags.WithFieldExtractor(grpc_ctxtags.CodeGenRequestFieldExtractor)),
			grpc_zap.UnaryServerInterceptor(app.Logger),
		),
	)

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", app.Config.Service.ListenAddress, app.Config.Service.Port))
	if err != nil {
		return fmt.Errorf("failed to open TCP socket: %w", err)
	}

	tokenservice.RegisterTokenServiceServer(grpcServer, endpoint.New(app.TokenManager))

	app.Logger.Info("Starting Token Service in gRPC mode",
		zap.Int("port", app.Config.Service.Port),
		zap.String("host", app.Config.Service.ListenAddress),
	)

	if err := grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}
