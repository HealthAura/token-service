package tokens

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	tokenservice "github.com/HealthAura/token-service/gen/go/v1"
	"github.com/HealthAura/token-service/public/jwt"
	"github.com/HealthAura/token-service/public/keys"
)

// Manager exposes an implementation to generate, validate, refresh, and revoke split tokens.
type Manager interface {
	// Generate creates a new access token and refresh token based on the provided claims and DPoP proof.
	Generate(ctx context.Context, req *tokenservice.TokenserviceGenerateRequest) (*tokenservice.TokenserviceGenerateResponse, error)
	// Refresh generates a new access token and refresh token using the provided refresh token and DPoP proof.
	Refresh(ctx context.Context, req *tokenservice.TokenserviceRefreshRequest) (*tokenservice.TokenserviceRefreshResponse, error)
	// GenerateNonce creates a new nonce based on the provided claims.
	GenerateNonce(ctx context.Context, req *tokenservice.TokenserviceGenerateNonceRequest) (*tokenservice.TokenserviceGenerateNonceResponse, error)
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
func (m manager) Generate(ctx context.Context, req *tokenservice.TokenserviceGenerateRequest) (*tokenservice.TokenserviceGenerateResponse, error) {
	now := time.Now()
	if err := validateGenerateRequest(req); err != nil {
		return nil, fmt.Errorf("failed to validate generate request: %w", err)
	}

	claims := jwt.APIClaimsToClaims(req.Claims)
	claims.IssuedAt = now.Unix()

	accessTokenTtl, err := strconv.ParseInt(*req.AccessTokenTtl, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse access token TTL: %w", err)
	}

	accessExpiry := now.Add(time.Duration(accessTokenTtl) * time.Minute).Unix()
	claims.ExpirationTime = accessExpiry
	claims.NotBefore = now.Unix()

	dpopTTL, err := strconv.ParseInt(*req.Dpop.TtlMinutes, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dpop TTL: %w", err)
	}

	token, err := m.orch.GenerateToken(ctx, jwt.GenerateTokenInput{
		Claims:      claims,
		Proof:       *req.Dpop.Proof,
		ExpectedHTM: *req.Dpop.WantClaims.Htm,
		ExpectedHTU: *req.Dpop.WantClaims.Htu,
		ExpectedRH:  *req.Dpop.WantClaims.Rh,
		DPopTTL:     time.Duration(dpopTTL) * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	claims = jwt.APIClaimsToClaims(req.Claims)
	claims.IssuedAt = now.Unix()

	refreshTokenTtl, err := strconv.ParseInt(*req.RefreshTokenTtl, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh TTL: %w", err)
	}

	refreshExpiry := now.Add(time.Duration(refreshTokenTtl) * time.Minute).Unix()
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
		Proof:               *req.Dpop.Proof,
		ExpectedHTM:         *req.Dpop.WantClaims.Htm,
		ExpectedHTU:         *req.Dpop.WantClaims.Htu,
		ExpectedRH:          *req.Dpop.WantClaims.Rh,
		DPopTTL:             time.Duration(dpopTTL) * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &tokenservice.TokenserviceGenerateResponse{
		AccessToken:        &token,
		RefreshToken:       &refreshToken,
		AccessTokenExpiry:  int64ToStrPtr(accessExpiry),
		RefreshTokenExpiry: int64ToStrPtr(refreshExpiry),
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
func (m manager) Refresh(ctx context.Context, req *tokenservice.TokenserviceRefreshRequest) (*tokenservice.TokenserviceRefreshResponse, error) {
	if err := validateRefreshRequest(req); err != nil {
		return nil, fmt.Errorf("failed to validate refresh request: %w", err)
	}

	if err := m.orch.ValidateAndVerify(ctx, jwt.ValidateAndVerifyInput{
		Token:          *req.RefreshToken,
		Proof:          *req.RefreshDpop.Proof,
		ExpectedHTM:    *req.RefreshDpop.WantClaims.Htm,
		ExpectedHTU:    *req.RefreshDpop.WantClaims.Htu,
		ExpectedRH:     *req.RefreshDpop.WantClaims.Rh,
		RequiredScopes: *req.RequiredScopes,
	}); err != nil {
		return nil, fmt.Errorf("failed to validate refresh token: %w", err)
	}

	token, err := m.orch.RevokeToken(ctx, jwt.RevokeTokenInput{Token: *req.RefreshToken})
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

	resp, err := m.Generate(ctx, &tokenservice.TokenserviceGenerateRequest{
		Claims:          jwt.ClaimsToAPIClaims(claims),
		AccessTokenTtl:  req.AccessTokenTtl,
		RefreshTokenTtl: req.RefreshTokenTtl,
		Dpop: &tokenservice.TokenserviceDPoP{
			Proof: req.NewTokenDpop.Proof,
			WantClaims: &tokenservice.TokenserviceDPoPClaims{
				Htm: req.NewTokenDpop.WantClaims.Htm,
				Htu: req.NewTokenDpop.WantClaims.Htu,
				Rh:  req.NewTokenDpop.WantClaims.Rh,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate new token pair: %w", err)
	}

	return &tokenservice.TokenserviceRefreshResponse{
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
func (m manager) GenerateNonce(ctx context.Context, req *tokenservice.TokenserviceGenerateNonceRequest) (*tokenservice.TokenserviceGenerateNonceResponse, error) {
	now := time.Now()
	if err := validateGenerateNonceRequest(req); err != nil {
		return nil, fmt.Errorf("failed to validate generate nonce request: %w", err)
	}

	nonceTTL, err := strconv.Atoi(*req.NonceTtl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nonce TTL: %w", err)
	}

	claims := jwt.APIClaimsToClaims(req.Claims)
	claims.IssuedAt = now.Unix()
	nonceExpiry := now.Add(time.Duration(nonceTTL) * time.Minute).Unix()
	claims.ExpirationTime = nonceExpiry
	claims.NotBefore = now.Unix()

	nonce, err := m.orch.GenerateNonce(ctx, jwt.GenerateNonceInput{
		Claims: claims,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	nonceExpiryStr := fmt.Sprintf("%d", nonceExpiry)
	return &tokenservice.TokenserviceGenerateNonceResponse{
		Nonce:     &nonce,
		ExpiresIn: &nonceExpiryStr,
	}, nil
}

// validateClaims ensures no nil pointers in TokenserviceClaims
func validateClaims(claims *tokenservice.TokenserviceClaims) error {
	var errorMessages []string

	if claims == nil {
		errorMessages = append(errorMessages, "claims is nil")
	}

	if claims != nil {
		if claims.Aud == nil {
			errorMessages = append(errorMessages, "aud is nil")
		}

		if claims.CustomClaims == nil {
			empty := make(map[string]interface{})
			claims.CustomClaims = &empty
		}

		if claims.Iss == nil {
			errorMessages = append(errorMessages, "iss is nil")
		}

		if claims.Jti == nil {
			errorMessages = append(errorMessages, "jti is nil")
		}

		if claims.Scopes == nil {
			claims.Scopes = &[]string{}
		}

		if claims.Sub == nil {
			errorMessages = append(errorMessages, "sub is nil")
		}
	}

	if len(errorMessages) > 0 {
		return errors.New("claims errors: " + strings.Join(errorMessages, ", "))
	}

	return nil
}

// validateGenerateRequest ensures no nil pointers in TokenserviceGenerateRequest
func validateGenerateRequest(req *tokenservice.TokenserviceGenerateRequest) error {
	var errorMessages []string

	if req == nil {
		errorMessages = append(errorMessages, "request is nil")
	}

	if req != nil {
		if err := validateClaims(req.Claims); err != nil {
			errorMessages = append(errorMessages, err.Error())
		}

		if err := validateDPoP(req.Dpop); err != nil {
			errorMessages = append(errorMessages, err.Error())
		}

		if req.AccessTokenTtl == nil {
			errorMessages = append(errorMessages, "access token TTL is nil")
		}

		if req.RefreshTokenTtl == nil {
			errorMessages = append(errorMessages, "refresh token TTL is nil")
		}
	}

	if len(errorMessages) > 0 {
		return errors.New("validation errors: " + strings.Join(errorMessages, ", "))
	}

	return nil
}

// validateRefreshRequest ensures no nil pointers in TokenserviceRefreshRequest
func validateRefreshRequest(req *tokenservice.TokenserviceRefreshRequest) error {
	var errorMessages []string

	if req == nil {
		errorMessages = append(errorMessages, "request is nil")
	}

	if req != nil {
		if req.AccessTokenTtl == nil {
			errorMessages = append(errorMessages, "access token TTL is nil")
		}

		if req.RefreshToken == nil {
			errorMessages = append(errorMessages, "refresh token is nil")
		}

		if req.RefreshTokenTtl == nil {
			errorMessages = append(errorMessages, "refresh token TTL is nil")
		}

		if err := validateDPoP(req.RefreshDpop); err != nil {
			errorMessages = append(errorMessages, fmt.Sprintf("refesh token dpop: %s", err.Error()))
		}

		if err := validateDPoP(req.NewTokenDpop); err != nil {
			errorMessages = append(errorMessages, fmt.Sprintf("new token dpop: %s", err.Error()))
		}

		if req.NewTokenDpop == nil {
			errorMessages = append(errorMessages, "new token DPoP is nil")
		}

		if req.RequiredScopes == nil {
			req.RequiredScopes = &[]string{}
		}
	}

	if len(errorMessages) > 0 {
		return errors.New("validation errors: " + strings.Join(errorMessages, ", "))
	}

	return nil
}

// validateGenerateNonceRequest ensures no nil pointers in TokenserviceGenerateRequest
func validateGenerateNonceRequest(req *tokenservice.TokenserviceGenerateNonceRequest) error {
	var errorMessages []string

	if req == nil {
		errorMessages = append(errorMessages, "request is nil")
	}

	if req != nil {
		if err := validateClaims(req.Claims); err != nil {
			errorMessages = append(errorMessages, err.Error())
		}

		if req.NonceTtl == nil {
			req.NonceTtl = strToPtr("2")
		}
	}

	if len(errorMessages) > 0 {
		return errors.New("validation errors: " + strings.Join(errorMessages, ", "))
	}

	return nil
}

// validateDPoP ensures no nil pointers in TokenserviceDPoP
func validateDPoP(dpop *tokenservice.TokenserviceDPoP) error {
	var errorMessages []string

	if dpop == nil {
		errorMessages = append(errorMessages, "dpop is nil")
	}

	if dpop != nil {
		if dpop.Proof == nil {
			errorMessages = append(errorMessages, "proof is nil")
		}

		if err := validateDPoPClaims(dpop.WantClaims); err != nil {
			errorMessages = append(errorMessages, err.Error())
		}

		if dpop.TtlMinutes == nil {
			dpop.TtlMinutes = strToPtr("1")
		}
	}

	if len(errorMessages) > 0 {
		return errors.New("dpop errors: " + strings.Join(errorMessages, ", "))
	}

	return nil
}

// validateDPoPClaims ensures no nil pointers in TokenserviceDPoPClaims
func validateDPoPClaims(claims *tokenservice.TokenserviceDPoPClaims) error {
	var errorMessages []string

	if claims == nil {
		errorMessages = append(errorMessages, "claims is nil")
	}

	if claims != nil {
		if claims.Htm == nil {
			errorMessages = append(errorMessages, "htm is nil")
		}

		if claims.Htu == nil {
			errorMessages = append(errorMessages, "htu is nil")
		}

		if claims.Rh == nil {
			errorMessages = append(errorMessages, "rh is nil")
		}
	}

	if len(errorMessages) > 0 {
		return errors.New("dpop claim errors: " + strings.Join(errorMessages, ", "))
	}

	return nil
}

func int64ToStrPtr(i int64) *string {
	s := strconv.FormatInt(i, 10)
	return &s
}

func strToPtr(str string) *string {
	return &str
}
