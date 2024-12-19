package jwtmock

import (
	"context"
	"errors"

	"github.com/HealthAura/token-service/public/jwt"
)

const (
	GenerateNonceError          = "GenerateNonceError"
	GenerateTokenError          = "GenerateTokenError"
	ValidateAndVerifyNonceError = "ValidateAndVerifyNonceError"
	ValidateAndVerifyError      = "ValidateAndVerifyError"
	RevokeTokenError            = "RevokeTokenError"
	fakeJWT                     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

var _ jwt.Orchestrator = MockOrchestrator{}

type MockOrchestrator struct {
	GenerateNonceError          bool
	GenerateTokenError          bool
	ValidateAndVerifyNonceError bool
	ValidateAndVerifyError      bool
	RevokeTokenError            bool
}

func (m MockOrchestrator) GenerateNonce(ctx context.Context, input jwt.GenerateNonceInput) (string, error) {
	if m.GenerateNonceError {
		return "", errors.New(GenerateNonceError)
	}

	return fakeJWT, nil
}

func (m MockOrchestrator) GenerateToken(ctx context.Context, input jwt.GenerateTokenInput) (string, error) {
	if m.GenerateTokenError {
		return "", errors.New(GenerateTokenError)
	}

	return fakeJWT, nil
}

func (m MockOrchestrator) ValidateAndVerifyNonce(ctx context.Context, input jwt.ValidateAndVerifyNonceInput) error {
	if m.ValidateAndVerifyNonceError {
		return errors.New(ValidateAndVerifyNonceError)
	}

	return nil
}

func (m MockOrchestrator) ValidateAndVerify(ctx context.Context, input jwt.ValidateAndVerifyInput) error {
	if m.ValidateAndVerifyError {
		return errors.New(ValidateAndVerifyError)
	}

	return nil
}

func (m MockOrchestrator) RevokeToken(ctx context.Context, input jwt.RevokeTokenInput) (string, error) {
	if m.RevokeTokenError {
		return "", errors.New(RevokeTokenError)
	}

	return fakeJWT, nil
}
