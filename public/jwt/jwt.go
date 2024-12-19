package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/HealthAura/token-service/public/jwt/tokenstore"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	tokenservice "github.com/HealthAura/token-service/gen/token-service.v1"
	"google.golang.org/protobuf/types/known/structpb"
)

type kmsClient interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

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
	kmsClient  kmsClient
	keyID      string
	tokenStore tokenstore.Store
	issuer     string
}

func New(kmsClient kmsClient, keyID string, issuer string, tokenStore tokenstore.Store) Orchestrator {
	return &orchestrator{
		keyID:      keyID,
		tokenStore: tokenStore,
		issuer:     issuer,
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

// ProtoClaimsToClaims converts the proto-generated Claims type to the package Claims type
func ProtoClaimsToClaims(protoClaims *tokenservice.Claims) Claims {
	claims := Claims{
		Issuer:   protoClaims.Issuer,
		Subject:  protoClaims.Subject,
		Audience: protoClaims.Audience,
		JWTID:    protoClaims.JwtId,
		Scopes:   protoClaims.Scopes,
	}

	// Convert custom claims
	claims.CustomClaims = make(map[string]interface{})
	for k, v := range protoClaims.CustomClaims {
		claims.CustomClaims[k] = structpbValueToInterface(v)
	}

	return claims
}

// Helper function to convert structpb.Value to interface{}
func structpbValueToInterface(value *structpb.Value) interface{} {
	switch value.Kind.(type) {
	case *structpb.Value_NullValue:
		return nil
	case *structpb.Value_NumberValue:
		return value.GetNumberValue()
	case *structpb.Value_StringValue:
		return value.GetStringValue()
	case *structpb.Value_BoolValue:
		return value.GetBoolValue()
	case *structpb.Value_StructValue:
		m := make(map[string]interface{})
		for k, v := range value.GetStructValue().Fields {
			m[k] = structpbValueToInterface(v)
		}
		return m
	case *structpb.Value_ListValue:
		list := make([]interface{}, len(value.GetListValue().Values))
		for i, v := range value.GetListValue().Values {
			list[i] = structpbValueToInterface(v)
		}
		return list
	default:
		return nil
	}
}

// ClaimsToProtoClaims converts the package Claims type to the proto-generated Claims type
func ClaimsToProtoClaims(claims Claims) *tokenservice.Claims {
	protoClaims := &tokenservice.Claims{
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: claims.Audience,
		JwtId:    claims.JWTID,
		Scopes:   claims.Scopes,
	}

	// Convert custom claims
	protoClaims.CustomClaims = make(map[string]*structpb.Value)
	for k, v := range claims.CustomClaims {
		protoClaims.CustomClaims[k] = interfaceToStructpbValue(v)
	}

	return protoClaims
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
