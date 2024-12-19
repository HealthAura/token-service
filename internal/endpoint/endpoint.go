package endpoint

import (
	"context"

	tokenservice "github.com/HealthAura/token-service/gen/token-service.v1"
	"github.com/HealthAura/token-service/internal/domain/tokens"
)

type tokenServiceServer struct {
	tokenManager tokens.Manager
	tokenservice.UnimplementedTokenServiceServer
}

func New(tokenManager tokens.Manager) tokenservice.TokenServiceServer {
	return &tokenServiceServer{
		tokenManager: tokenManager,
	}
}

// Generate creates a new access token and refresh token based on the provided claims and DPoP proof.
func (t tokenServiceServer) Generate(ctx context.Context, req *tokenservice.GenerateRequest) (*tokenservice.GenerateResponse, error) {
	return t.tokenManager.Generate(ctx, req)
}

// Refresh generates a new access token and refresh token using the provided refresh token and DPoP proof.
func (t tokenServiceServer) Refresh(ctx context.Context, req *tokenservice.RefreshRequest) (*tokenservice.RefreshResponse, error) {
	return t.tokenManager.Refresh(ctx, req)
}

// GenerateNonce creates a new nonce based on the provided claims.
func (t tokenServiceServer) GenerateNonce(ctx context.Context, req *tokenservice.GenerateNonceRequest) (*tokenservice.GenerateNonceResponse, error) {
	return t.tokenManager.GenerateNonce(ctx, req)
}
