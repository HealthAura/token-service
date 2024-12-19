package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type ValidateAndVerifyNonceInput struct {
	Nonce          string
	RequiredScopes []string
}

type ValidateAndVerifyInput struct {
	Token          string
	Proof          string
	ExpectedHTM    string
	ExpectedHTU    string
	ExpectedRH     string
	RequiredScopes []string
}

func (o orchestrator) ValidateAndVerifyNonce(ctx context.Context, input ValidateAndVerifyNonceInput) error {
	if _, err := o.validateAndVerify(ctx, input.Nonce, input.RequiredScopes); err != nil {
		return fmt.Errorf("failed to validate and verify nonce: %w", err)
	}

	if _, err := o.RevokeToken(ctx, RevokeTokenInput{Token: input.Nonce}); err != nil {
		return fmt.Errorf("failed to delete nonce from token store: %w", err)
	}

	return nil
}

func (o orchestrator) ValidateAndVerify(ctx context.Context, input ValidateAndVerifyInput) error {
	token, err := o.validateAndVerify(ctx, input.Token, input.RequiredScopes)
	if err != nil {
		return err
	}

	if err := o.validateVerifyBoundProof(ctx, token, input.Proof, input.ExpectedHTM, input.ExpectedHTU, input.ExpectedRH, time.Minute, input.Token); err != nil {
		return fmt.Errorf("failed to validate and verify DPoP: %w", err)
	}

	return nil
}

func (o orchestrator) validateAndVerify(ctx context.Context, signature string, requiredScopes []string) (string, error) {
	token, err := o.tokenStore.GetToken(ctx, signature)
	if err != nil {
		return "", fmt.Errorf("failed to get token from token store: %w", err)
	}

	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
		return "", errors.New("invalid token JWT format")
	}

	header, err := base64.RawURLEncoding.DecodeString(tokenParts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode token header: %w", err)
	}

	var tokenHeader struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(header, &tokenHeader); err != nil {
		return "", fmt.Errorf("failed to parse token header: %w", err)
	}

	if tokenHeader.Alg != "ES256" {
		return "", fmt.Errorf("unexpected signing method: %v", tokenHeader.Alg)
	}

	claimsPayload, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode token payload: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsPayload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse token claims: %w", err)
	}

	// Validate claims
	now := time.Now()
	if claims.Issuer != o.issuer {
		return "", fmt.Errorf("invalid issuer: expected %s, got %s", o.issuer, claims.Issuer)
	}

	if time.Unix(claims.ExpirationTime, 0).Before(now) {
		return "", errors.New("token has expired")
	}
	if time.Unix(claims.NotBefore, 0).After(now) {
		return "", errors.New("token is not yet valid")
	}
	if time.Unix(claims.IssuedAt, 0).After(now) {
		return "", errors.New("token issue time is in the future")
	}
	if claims.JWTID == "" {
		return "", errors.New("token ID (jti) is missing")
	}

	// Validate scopes
	if err := validateScopes(claims.Scopes, requiredScopes); err != nil {
		return "", fmt.Errorf("scope validation failed: %w", err)
	}

	// Verify the signature using KMS
	message := []byte(tokenParts[0] + "." + tokenParts[1])
	signatureBytes, err := base64.RawURLEncoding.DecodeString(tokenParts[2])
	if err != nil {
		return "", fmt.Errorf("failed to decode signature: %w", err)
	}

	verifyInput := &kms.VerifyInput{
		KeyId:            &o.keyID,
		Message:          message,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
		Signature:        signatureBytes,
	}

	verifyOutput, err := o.kmsClient.Verify(ctx, verifyInput)
	if err != nil {
		return "", fmt.Errorf("failed to verify signature with KMS: %w", err)
	}

	if !verifyOutput.SignatureValid {
		return "", errors.New("token JWT signature is invalid")
	}

	return token, nil
}

// validateScopes checks if the token's scopes include all required scopes
func validateScopes(tokenScopes []string, requiredScopes []string) error {
	if len(requiredScopes) == 0 && len(tokenScopes) == 0 {
		return nil
	}

	if len(tokenScopes) == 0 && len(requiredScopes) > 0 {
		return errors.New("token has no scopes")
	}

	for _, tokenScope := range tokenScopes {
		tokenScopes := strings.Fields(tokenScope)
		tokenScopeMap := make(map[string]bool)
		for _, scope := range tokenScopes {
			tokenScopeMap[scope] = true
		}

		for _, requiredScope := range requiredScopes {
			if !tokenScopeMap[requiredScope] {
				return fmt.Errorf("missing required scope: %s", requiredScope)
			}
		}
	}

	return nil
}
