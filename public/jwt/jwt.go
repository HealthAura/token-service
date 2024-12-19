package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/HealthAura/token-service/public/jwt/tokenstore"

	tokenservice "github.com/HealthAura/token-service/gen/go/v1"
	mkms "github.com/HealthAura/token-service/public/keys/kms"
	"google.golang.org/protobuf/types/known/structpb"
)

type Orchestrator interface {
	GenerateNonce(ctx context.Context, input GenerateNonceInput) (string, error)
	GenerateToken(ctx context.Context, input GenerateTokenInput) (string, error)
	ValidateAndVerifyNonce(ctx context.Context, input ValidateAndVerifyNonceInput) error
	ValidateAndVerify(ctx context.Context, input ValidateAndVerifyInput) error
	RevokeToken(ctx context.Context, input RevokeTokenInput) (string, error)
}

type RevokeTokenInput struct {
	Token string
}

// Claims represents the structure of claims in our JWT
type Claims struct {
	Issuer         string   `json:"iss"`
	Subject        string   `json:"sub"`
	Audience       string   `json:"aud"`
	ExpirationTime int64    `json:"exp"`
	NotBefore      int64    `json:"nbf"`
	IssuedAt       int64    `json:"iat"`
	JWTID          string   `json:"jti"`
	ATH            string   `json:"ath"` // associated token hash, used for mapping refresh tokens to access tokens
	Scopes         []string `json:"scopes"`
	CustomClaims   map[string]interface{}
}

type orchestrator struct {
	kmsClient  mkms.KMS
	keyID      string
	tokenStore tokenstore.Store
	issuer     string
}

func New(kmsClient mkms.KMS, keyID string, issuer string, tokenStore tokenstore.Store) Orchestrator {
	return &orchestrator{
		keyID:      keyID,
		tokenStore: tokenStore,
		issuer:     issuer,
		kmsClient:  kmsClient,
	}
}

func (o orchestrator) RevokeToken(ctx context.Context, input RevokeTokenInput) (string, error) {
	token, err := o.tokenStore.GetToken(ctx, input.Token)
	if err != nil {
		return "", fmt.Errorf("failed to get token from token store: %w", err)
	}

	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
		return "", errors.New("invalid token JWT format")
	}

	claimsPayload, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode token payload: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsPayload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse token claims: %w", err)
	}

	// If we have an associated token we need to revoke that first
	if claims.ATH != "" {
		if err := o.tokenStore.DeleteTokenByATH(ctx, claims.ATH); err != nil {
			if _, ok := err.(tokenstore.NotFoundErr); !ok { // If the token is not found we don't care because it may already be ejected from cache
				return "", fmt.Errorf("failed to delete associated token: %w", err)
			}
		}
	}

	return token, o.tokenStore.DeleteToken(ctx, input.Token)
}

// APIClaimsToClaims converts the proto-generated Claims type to the package Claims type
func APIClaimsToClaims(apilaims *tokenservice.TokenserviceClaims) Claims {
	claims := Claims{
		Issuer:   *apilaims.Iss,
		Subject:  *apilaims.Sub,
		Audience: *apilaims.Aud,
		JWTID:    *apilaims.Jti,
		Scopes:   *apilaims.Scopes,
	}

	if apilaims.CustomClaims != nil {
		claims.CustomClaims = make(map[string]interface{})
		for k, v := range *apilaims.CustomClaims {
			claims.CustomClaims[k] = v
		}
	}

	return claims
}

// ClaimsToAPIClaims converts the package Claims type to the open API Claims type
func ClaimsToAPIClaims(claims Claims) *tokenservice.TokenserviceClaims {
	apiClaims := &tokenservice.TokenserviceClaims{
		Iss:    &claims.Issuer,
		Sub:    &claims.Subject,
		Aud:    &claims.Audience,
		Jti:    &claims.JWTID,
		Scopes: &claims.Scopes,
	}

	// Convert custom claims
	apiClaims.CustomClaims = &map[string]interface{}{}
	for k, v := range claims.CustomClaims {
		(*apiClaims.CustomClaims)[k] = interfaceToStructpbValue(v)
	}

	return apiClaims
}

// Helper function to convert interface{} to structpb.Value
func interfaceToStructpbValue(v interface{}) *structpb.Value {
	switch val := v.(type) {
	case nil:
		return structpb.NewNullValue()
	case float64:
		return structpb.NewNumberValue(val)
	case string:
		return structpb.NewStringValue(val)
	case bool:
		return structpb.NewBoolValue(val)
	case map[string]interface{}:
		structValue, _ := structpb.NewStruct(val)
		return structpb.NewStructValue(structValue)
	case []interface{}:
		listValue, _ := structpb.NewList(val)
		return structpb.NewListValue(listValue)
	default:
		// Handle other types or return null for unsupported types
		return structpb.NewNullValue()
	}
}
