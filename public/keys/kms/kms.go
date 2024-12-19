package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

const (
	SignErr   = "Sign error"
	VerifyErr = "Verify error"
)

type KMS interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

type MockKMSClient struct {
	PrivateKey *ecdsa.PrivateKey
	SignErr    bool
	VerifyErr  bool
}

func NewMock(privateKey *ecdsa.PrivateKey, signErr bool, verifyErr bool) KMS {
	return MockKMSClient{
		PrivateKey: privateKey,
		SignErr:    signErr,
		VerifyErr:  verifyErr,
	}
}

func (m MockKMSClient) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	if m.SignErr {
		return nil, errors.New(SignErr)
	}

	hash := sha256.Sum256(params.Message)
	r, s, err := ecdsa.Sign(rand.Reader, m.PrivateKey, hash[:])
	if err != nil {
		return nil, err
	}

	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)

	return &kms.SignOutput{
		Signature: signature,
	}, nil
}

func (m MockKMSClient) Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	if m.VerifyErr {
		return nil, errors.New(VerifyErr)
	}

	hash := sha256.Sum256(params.Message)

	r := new(big.Int).SetBytes(params.Signature[:len(params.Signature)/2])
	s := new(big.Int).SetBytes(params.Signature[len(params.Signature)/2:])

	valid := ecdsa.Verify(&m.PrivateKey.PublicKey, hash[:], r, s)

	return &kms.VerifyOutput{
		SignatureValid: valid,
	}, nil
}
