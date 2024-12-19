package kmsmock

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type MockKMSClient struct {
	PrivateKey *ecdsa.PrivateKey
}

func (m MockKMSClient) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
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
	hash := sha256.Sum256(params.Message)

	r := new(big.Int).SetBytes(params.Signature[:len(params.Signature)/2])
	s := new(big.Int).SetBytes(params.Signature[len(params.Signature)/2:])

	valid := ecdsa.Verify(&m.PrivateKey.PublicKey, hash[:], r, s)

	return &kms.VerifyOutput{
		SignatureValid: valid,
	}, nil
}
