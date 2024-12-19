package logging

import (
	"context"

	"github.com/HealthAura/token-service/internal/metadata"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Middleware struct {
	log *zap.Logger
}

func New(log *zap.Logger) Middleware {
	return Middleware{
		log: log,
	}
}

func (m Middleware) Middleware(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md := metadata.Get(ctx)
	m.log.With(
		zap.String("method", info.FullMethod),
		zap.String("user-agent", md.UserAgent),
		zap.String("x-correlation-id", md.CorrelationID),
	).Info("Received incoming request.")

	resp, err := handler(ctx, req)
	if err != nil {
		m.log.With(
			zap.String("method", info.FullMethod),
			zap.Error(err),
			zap.String("user-agent", md.UserAgent),
			zap.String("x-correlation-id", md.CorrelationID),
		).Info("Error processing incoming request.")

		return resp, status.Errorf(codes.Internal, "an issue occured with the correlation id '%s'", md.CorrelationID)
	}

	m.log.With(
		zap.String("method", info.FullMethod),
		zap.String("user-agent", md.UserAgent),
		zap.String("x-correlation-id", md.CorrelationID),
	).Info("Processed incoming request.")

	return resp, nil
}
