package jwt

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/HealthAura/token-service/public/keys"
	"github.com/golang-jwt/jwt/v4"
)

func (o orchestrator) validateVerifyUnboundProof(ctx context.Context, proof, expectedHTM, expectedHTU, expectedRH string, ttl time.Duration) error {
	if err := verifySignature(proof); err != nil {
		return err
	}

	if err := o.validateClaims(ctx, proof, expectedHTM, expectedHTU, expectedRH, ttl, ""); err != nil {
		return err
	}

	return nil
}

func (o orchestrator) validateVerifyBoundProof(ctx context.Context, token, proof string, expectedHTM, expectedHTU, expectedRH string, ttl time.Duration, tokenSignature string) error {
	if err := o.verifyThumbprint(ctx, token, proof); err != nil {
		return err
	}

	if err := verifySignature(proof); err != nil {
		return err
	}

	if err := o.validateClaims(ctx, proof, expectedHTM, expectedHTU, expectedRH, ttl, tokenSignature); err != nil {
		return err
	}

	return nil
}

func (o orchestrator) verifyThumbprint(ctx context.Context, token, proof string) error {
	// Parse the access token JWT without verifying the signature
	accessToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse access token JWT: %w", err)
	}

	// Extract the JKT from the access token claims
	claims, ok := accessToken.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("invalid claims in access token")
	}

	cnf, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		return errors.New("missing or invalid 'cnf' claim in access token")
	}

	jkt, ok := cnf["jkt"].(string)
	if !ok {
		return errors.New("missing or invalid 'jkt' in 'cnf' claim")
	}

	calculatedJKT, err := extractPublicKeyHash(proof)
	if err != nil {
		return fmt.Errorf("failed to extract public key hash: %w", err)
	}

	// Compare the calculated JKT with the JKT from the access token
	if calculatedJKT != jkt {
		return errors.New("DPoP proof public key does not match the JKT in the access token")
	}

	return nil
}

// VerifySignature verifies the signature of the DPoP proof
func verifySignature(proof string) error {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return errors.New("invalid token format")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode header: %w", err)
	}

	var header struct {
		Alg string                 `json:"alg"`
		JWK map[string]interface{} `json:"jwk"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("failed to parse header: %w", err)
	}

	if header.Alg != "ES256" {
		return errors.New("unsupported algorithm")
	}

	xStr, xOk := header.JWK["x"].(string)
	yStr, yOk := header.JWK["y"].(string)
	if !xOk || !yOk {
		return errors.New("missing x or y coordinate in JWK")
	}

	x, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return fmt.Errorf("failed to decode x coordinate: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return fmt.Errorf("failed to decode y coordinate: %w", err)
	}

	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}

	// Verify the signature
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	if len(signatureBytes) != 64 {
		return errors.New("invalid signature length")
	}

	r := new(big.Int).SetBytes(signatureBytes[:32])
	s := new(big.Int).SetBytes(signatureBytes[32:])

	// Hash the header and payload
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(parts[0] + "." + parts[1]))
	hash := hasher.Sum(nil)

	// Verify the signature
	if ecdsa.Verify(pub, hash, r, s) {
		return nil
	}

	return errors.New("dpop proof contains invalid signature")
}

func (o orchestrator) validateClaims(ctx context.Context, proof, expectedHTM, expectedHTU, expectedRH string, ttl time.Duration, tokenSignature string) error {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return errors.New("invalid token format")
	}

	// Decode the payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims DPoPClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return fmt.Errorf("failed to parse claims: %w", err)
	}

	// Validate JWT (jti)
	if claims.JWT == "" {
		return errors.New("missing jti claim")
	}

	if err = validateHTMClaim(claims.HTM, expectedHTM); err != nil {
		return err
	}

	if err = validateHTUClaim(claims.HTU, expectedHTU); err != nil {
		return err
	}

	if err = validateIATClaim(claims.IAT, ttl); err != nil {
		return err
	}

	if err = validateATHClaim(claims.ATH, tokenSignature); err != nil {
		return err
	}

	if err = o.validateNonceClaim(ctx, claims.Nonce); err != nil {
		return err
	}

	if err = validateRHClaim(claims.RH, expectedRH); err != nil {
		return err
	}

	return nil
}

func validateRHClaim(rh, expectedRH string) error {
	if rh == "" {
		return errors.New("missing rh claim")
	}

	if rh != expectedRH {
		return fmt.Errorf("rh claim mismatch: expected %s, got %s", expectedRH, rh)
	}

	return nil
}

func validateHTMClaim(htm, expectedHTM string) error {
	if htm == "" {
		return errors.New("missing htm claim")
	}

	if htm != expectedHTM {
		return fmt.Errorf("htm claim mismatch: expected %s, got %s", expectedHTM, htm)
	}

	return nil
}

func validateHTUClaim(htu, expectedHTU string) error {
	if htu == "" {
		return errors.New("missing htu claim")
	}

	if htu != expectedHTU {
		return fmt.Errorf("htu claim mismatch: expected %s, got %s", expectedHTU, htu)
	}

	return nil
}

func validateIATClaim(iat int64, ttl time.Duration) error {
	if iat == 0 {
		return errors.New("missing iat claim")
	}

	issuedAt := time.Unix(iat, 0)
	if time.Since(issuedAt) > ttl {
		return errors.New("token too old")
	}

	return nil
}

func validateATHClaim(ath string, token string) error {

	if token != "" {
		tokenHash, err := keys.Sha256Hash([]byte(token))
		if err != nil {
			return fmt.Errorf("failed to hash token: %w", err)
		}

		if base64.RawURLEncoding.EncodeToString(tokenHash) != ath {
			return errors.New("ath does not match token hash")
		}
	}

	return nil
}

func (o orchestrator) validateNonceClaim(ctx context.Context, nonceClaim string) error {
	if nonceClaim == "" {
		return errors.New("missing nonce claim")
	}

	if err := o.ValidateAndVerifyNonce(ctx, ValidateAndVerifyNonceInput{
		Nonce:          nonceClaim,
		RequiredScopes: []string{"dpopnonce"},
	}); err != nil {
		return err
	}

	return nil
}

// DPoPClaims represents the claims in a DPoP proof
type DPoPClaims struct {
	JWT   string `json:"jti"` // Unique identifier for the DPoP proof JWT
	HTM   string `json:"htm"` // HTTP method
	HTU   string `json:"htu"` // HTTP URI
	IAT   int64  `json:"iat"` // Issued at time
	ATH   string `json:"ath"` // Hash of the access token (optional)
	RH    string `json:"rh"`  // sha256 hash base64 raw url encoding of the request body
	Nonce string `json:"nonce"`
}

// Valid implements the jwt.Claims interface
func (c DPoPClaims) Valid() error {
	if c.JWT == "" {
		return errors.New("jti claim is required")
	}
	if c.HTM == "" {
		return errors.New("htm claim is required")
	}
	if c.HTU == "" {
		return errors.New("htu claim is required")
	}
	if c.IAT == 0 {
		return errors.New("iat claim is required")
	}

	if c.Nonce == "" {
		return errors.New("nonce claim is required")
	}

	if c.RH == "" {
		return errors.New("request hash is required")
	}

	return nil
}

// Encode creates a DPoP proof JWT
func EncodeProof(privateKey *ecdsa.PrivateKey, claims DPoPClaims) (string, error) {
	// Create the header
	header := map[string]interface{}{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
		},
	}

	// Create a new token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header = header

	// Sign the token
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign DPoP token: %w", err)
	}

	return signedToken, nil
}

func CreateDisgest(req interface{}) (string, error) {
	v, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	v, err = keys.Sha256Hash(v)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(v), nil
}

func extractPublicKeyHash(proof string) (string, error) {
	proofToken, _, err := new(jwt.Parser).ParseUnverified(proof, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse DPoP proof JWT: %w", err)
	}

	jwk, ok := proofToken.Header["jwk"].(map[string]interface{})
	if !ok {
		return "", errors.New("invalid or missing JWK in DPoP proof header")
	}

	rawKey := []byte{0x04}

	// Append X coordinate
	if x, err := base64.RawURLEncoding.DecodeString(jwk["x"].(string)); err == nil {
		rawKey = append(rawKey, x...)
	} else {
		return "", fmt.Errorf("failed to decode x coordinate: %w", err)
	}

	if y, err := base64.RawURLEncoding.DecodeString(jwk["y"].(string)); err == nil {
		rawKey = append(rawKey, y...)
	} else {
		return "", fmt.Errorf("failed to decode y coordinate: %w", err)
	}

	ecdhKey, err := ecdh.P256().NewPublicKey(rawKey)
	if err != nil {
		return "", fmt.Errorf("failed to create ECDH public key: %w", err)
	}

	thumbprint, err := keys.Sha256Hash(ecdhKey.Bytes())
	if err != nil {
		return "", fmt.Errorf("failed to calculate thumbprint hash: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}
