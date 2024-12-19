package jwt

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type GenerateNonceInput struct {
	Claims Claims
}

type GenerateTokenInput struct {
	Claims              Claims
	SkipProofValidation bool

	// DPoP claims
	Proof       string
	ExpectedHTM string
	ExpectedHTU string
	ExpectedRH  string
	DPopTTL     time.Duration
}

func (o orchestrator) GenerateNonce(ctx context.Context, input GenerateNonceInput) (string, error) {
	return o.generateJWT(ctx, input.Claims, input.Claims.Scopes, nil)
}

func (o orchestrator) GenerateToken(ctx context.Context, input GenerateTokenInput) (string, error) {
	if !input.SkipProofValidation {
		if err := o.validateVerifyUnboundProof(
			ctx,
			input.Proof,
			input.ExpectedHTM,
			input.ExpectedHTU,
			input.ExpectedRH,
			time.Minute,
		); err != nil {
			return "", fmt.Errorf("failed to validate DPoP proof: %w", err)
		}
	}

	dpopThumbprintHash, err := extractPublicKeyHash(input.Proof)
	if err != nil {
		return "", fmt.Errorf("failed to extract public key hash: %w", err)
	}

	dpopClaims := map[string]interface{}{
		"cnf": map[string]interface{}{
			"jkt": dpopThumbprintHash,
		},
	}

	return o.generateJWT(ctx, input.Claims, input.Claims.Scopes, dpopClaims)
}

func (o orchestrator) generateJWT(ctx context.Context, claims Claims, scopes []string, additionalClaims map[string]interface{}) (string, error) {
	jwtClaims := jwt.MapClaims{
		"iss": o.issuer,
		"sub": claims.Subject,
		"aud": claims.Audience,
		"exp": claims.ExpirationTime,
		"nbf": claims.NotBefore,
		"iat": claims.IssuedAt,
		"jti": uuid.New().String(),
		"ath": claims.ATH,
	}

	if len(scopes) > 0 {
		jwtClaims["scopes"] = scopes
	}

	for key, value := range claims.CustomClaims {
		jwtClaims[key] = value
	}

	for key, value := range additionalClaims {
		jwtClaims[key] = value
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwtClaims)

	unsignedToken, err := token.SigningString()
	if err != nil {
		return "", err
	}

	signInput := &kms.SignInput{
		KeyId:            aws.String(o.keyID),
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
		Message:          []byte(unsignedToken),
		MessageType:      types.MessageTypeRaw,
	}

	signOutput, err := o.kmsClient.Sign(ctx, signInput)
	if err != nil {
		return "", err
	}

	signature := base64.RawURLEncoding.EncodeToString(signOutput.Signature)
	fullToken := unsignedToken + "." + signature
	if err = o.tokenStore.StoreToken(ctx, fullToken, time.Hour); err != nil {
		return "", fmt.Errorf("failed to store split token: %w", err)
	}

	return signature, nil
}
