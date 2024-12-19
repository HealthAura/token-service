package tokens

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	tokenservice "github.com/HealthAura/token-service/gen/token-service.v1"
	"github.com/HealthAura/token-service/public/jwt"
	"github.com/HealthAura/token-service/public/keys"
)

// Manager exposes an implementation to generate, validate, refresh, and revoke split tokens.
type Manager interface {
	// Generate creates a new access token and refresh token based on the provided claims and DPoP proof.
	Generate(ctx context.Context, req *tokenservice.GenerateRequest) (*tokenservice.GenerateResponse, error)
	// Refresh generates a new access token and refresh token using the provided refresh token and DPoP proof.
	Refresh(ctx context.Context, req *tokenservice.RefreshRequest) (*tokenservice.RefreshResponse, error)
	// GenerateNonce creates a new nonce based on the provided claims.
	GenerateNonce(ctx context.Context, req *tokenservice.GenerateNonceRequest) (*tokenservice.GenerateNonceResponse, error)
}

type manager struct {
	orch jwt.Orchestrator
}

// New returns a Manager implementation.
//
// Parameters:
//   - privateKey: The private key used for signing tokens.
//   - store: The tokenstore.Store object used for storing tokens.
//   - orch: The jwt.Orchestrator object used for orchestrating JWT operations.
//
// Returns:
//   - Manager: The newly created Manager instance.
func New(orch jwt.Orchestrator) Manager {
	m := manager{
		orch: orch,
	}

	return m
}

// Generate creates a new access token and refresh token based on the provided claims and DPoP proof.
//
// Parameters:
//   - ctx: The context.Context object for the request.
//   - req: The tokenservice.GenerateRequest object containing the claims and DPoP proof.
//
// Returns:
//   - *tokenservice.GenerateResponse: The response object containing the generated access token, refresh token, and their expiration times.
//   - error: An error if any occurred during the token generation.
func (m manager) Generate(ctx context.Context, req *tokenservice.GenerateRequest) (*tokenservice.GenerateResponse, error) {
	now := time.Now()

	claims := jwt.ProtoClaimsToClaims(req.Claims)
	claims.IssuedAt = now.Unix()
	accessExpiry := now.Add(time.Duration(req.AccessTokenTtl) * time.Minute).Unix()
	claims.ExpirationTime = accessExpiry
	claims.NotBefore = now.Unix()

	token, err := m.orch.GenerateToken(ctx, jwt.GenerateTokenInput{
		Claims:      claims,
		Proof:       req.Dpop.Proof,
		ExpectedHTM: req.Dpop.WantClaims.Htm,
		ExpectedHTU: req.Dpop.WantClaims.Htu,
		ExpectedRH:  req.Dpop.WantClaims.Rh,
		DPopTTL:     time.Duration(req.Dpop.TtlMinutes) * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	claims = jwt.ProtoClaimsToClaims(req.Claims)
	claims.IssuedAt = now.Unix()

	refreshExpiry := now.Add(time.Duration(req.RefreshTokenTtl) * time.Minute).Unix()
	claims.ExpirationTime = refreshExpiry
	claims.NotBefore = now.Unix()

	// Set the associated token to the refresh token
	v, err := keys.Sha256Hash([]byte(token))
	if err != nil {
		return nil, fmt.Errorf("failed to hash token for ath: %w", err)
	}
	claims.ATH = base64.RawURLEncoding.EncodeToString(v)

	refreshToken, err := m.orch.GenerateToken(ctx, jwt.GenerateTokenInput{
		Claims:              claims,
		SkipProofValidation: true,
		Proof:               req.Dpop.Proof,
		ExpectedHTM:         req.Dpop.WantClaims.Htm,
		ExpectedHTU:         req.Dpop.WantClaims.Htu,
		ExpectedRH:          req.Dpop.WantClaims.Rh,
		DPopTTL:             time.Duration(req.Dpop.TtlMinutes) * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &tokenservice.GenerateResponse{
		AccessToken:        token,
		RefreshToken:       refreshToken,
		AccessTokenExpiry:  accessExpiry,
		RefreshTokenExpiry: refreshExpiry,
	}, nil
}

// Refresh generates a new access token and refresh token using the provided refresh token and DPoP proof.
//
// Parameters:
//   - ctx: The context.Context object for the request.
//   - req: The tokenservice.RefreshRequest object containing the refresh token and DPoP proof.
//
// Returns:
//   - *tokenservice.RefreshResponse: The response object containing the new access token, refresh token, and their expiration times.
//   - error: An error if any occurred during the token refresh process.
func (m manager) Refresh(ctx context.Context, req *tokenservice.RefreshRequest) (*tokenservice.RefreshResponse, error) {
	if err := m.orch.ValidateAndVerify(ctx, jwt.ValidateAndVerifyInput{
		Token:          req.RefreshToken,
		Proof:          req.RefreshDpop.Proof,
		ExpectedHTM:    req.RefreshDpop.WantClaims.Htm,
		ExpectedHTU:    req.RefreshDpop.WantClaims.Htu,
		ExpectedRH:     req.RefreshDpop.WantClaims.Rh,
		RequiredScopes: req.RequiredScopes,
	}); err != nil {
		return nil, fmt.Errorf("failed to validate refresh token: %w", err)
	}

	token, err := m.orch.RevokeToken(ctx, jwt.RevokeTokenInput{Token: req.RefreshToken})
	if err != nil {
		return nil, fmt.Errorf("failed to revoke refresh token pair: %w", err)
	}

	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
		return nil, errors.New("invalid token JWT format")
	}

	claimsPayload, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	var claims jwt.Claims
	if err := json.Unmarshal(claimsPayload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}

	resp, err := m.Generate(ctx, &tokenservice.GenerateRequest{
		Claims:          jwt.ClaimsToProtoClaims(claims),
		AccessTokenTtl:  req.AccessTokenTtl,
		RefreshTokenTtl: req.RefreshTokenTtl,
		Dpop: &tokenservice.DPoP{
			Proof: req.NewTokenDpop.Proof,
			WantClaims: &tokenservice.DPoPClaims{
				Htm: req.NewTokenDpop.WantClaims.Htm,
				Htu: req.NewTokenDpop.WantClaims.Htu,
				Rh:  req.NewTokenDpop.WantClaims.Rh,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate new token pair: %w", err)
	}

	return &tokenservice.RefreshResponse{
		AccessToken:        resp.AccessToken,
		RefreshToken:       resp.RefreshToken,
		AccessTokenExpiry:  resp.AccessTokenExpiry,
		RefreshTokenExpiry: resp.RefreshTokenExpiry,
	}, nil
}

// GenerateNonce creates a new nonce based on the provided claims.
//
// Parameters:
//   - ctx: The context.Context object for the request.
//   - req: The tokenservice.GenerateNonceRequest object containing the claims.
//
// Returns:
//   - *tokenservice.GenerateNonceResponse: The response object containing the generated nonce and its expiration time.
//   - error: An error if any occurred during the nonce generation.
func (m manager) GenerateNonce(ctx context.Context, req *tokenservice.GenerateNonceRequest) (*tokenservice.GenerateNonceResponse, error) {
	now := time.Now()

	claims := jwt.ProtoClaimsToClaims(req.Claims)
	claims.IssuedAt = now.Unix()
	nonceExpiry := now.Add(time.Duration(req.NonceTtl) * time.Minute).Unix()
	claims.ExpirationTime = nonceExpiry
	claims.NotBefore = now.Unix()

	nonce, err := m.orch.GenerateNonce(ctx, jwt.GenerateNonceInput{
		Claims: claims,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return &tokenservice.GenerateNonceResponse{
		Nonce:     nonce,
		ExpiresIn: nonceExpiry,
	}, nil
}
