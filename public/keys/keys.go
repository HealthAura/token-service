package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
)

type signature struct {
	R, S *big.Int
}

// SerializePrivateKey - Serializes a ecdsa private key to pem format
func SerializePrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	derFormat, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derFormat,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// serializePrivateKey serializes an ECDSA private key to a 32-byte slice.
func SerializePrivateKeyToSlice(privateKey *ecdsa.PrivateKey) []byte {
	// Ensure the D value is 32 bytes, padding with leading zeros if necessary.
	byteLen := (privateKey.Curve.Params().BitSize + 7) / 8
	dBytes := privateKey.D.Bytes()
	serializedKey := make([]byte, byteLen)

	copy(serializedKey[byteLen-len(dBytes):], dBytes)
	return serializedKey
}

// DeserializePrivateKey - Deserialize a ecdsa private key from pem format
func DeserializePrivateKey(privateKey []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	deserializedKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse private key")
	}

	return deserializedKey, nil
}

// SerializePublicKey - serializes a public key in ecdsa form to bytes
func SerializePublicKey(publicKey *ecdsa.PublicKey) []byte {
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()

	expectedByteLen := (publicKey.Curve.Params().BitSize + 7) / 8

	xBytesPadded := append(make([]byte, expectedByteLen-len(xBytes)), xBytes...)
	yBytesPadded := append(make([]byte, expectedByteLen-len(yBytes)), yBytes...)

	return append([]byte{0x04}, append(xBytesPadded, yBytesPadded...)...)
}

// DeserializePublicKey = deserializes a public key in bytes to ecdsa form
func DeserializePublicKey(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	if len(pubKeyBytes) != 65 || pubKeyBytes[0] != 0x04 {
		return nil, fmt.Errorf("invalid public key format")
	}

	curve := elliptic.P256()
	expectedByteLen := (curve.Params().BitSize + 7) / 8

	x := new(big.Int).SetBytes(pubKeyBytes[1 : 1+expectedByteLen])
	y := new(big.Int).SetBytes(pubKeyBytes[1+expectedByteLen:])

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// SerializeSignature - Serializes a signature's r and s values into asn1 standard
func SerializeSignature(r, s *big.Int) ([]byte, error) {
	sig := signature{R: r, S: s}
	return asn1.Marshal(sig)
}

// DeserializeSignature - deserializes an ASN.1 DER encoded ECDSA signature into its r and s components.
func DeserializeSignature(sigBytes []byte) (*big.Int, *big.Int, error) {
	var sig signature
	_, err := asn1.Unmarshal(sigBytes, &sig)
	if err != nil {
		return nil, nil, fmt.Errorf("error deserializing signature: %v", err)
	}
	return sig.R, sig.S, nil
}

// Sign - signs the payload using the ecdsa private key
func Sign(privKey *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
	hashedPayload, err := Sha256Hash(payload)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hashedPayload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign message")
	}

	signature, err := SerializeSignature(r, s)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// Verify - verifies the payload with asn1 formatted signature and serialized public key
func Verify(publicKey, payload, signature []byte) (bool, error) {
	ecdsaPublicKey, err := DeserializePublicKey(publicKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to deserialize public key")
	}

	r, s, err := DeserializeSignature(signature)
	if err != nil {
		return false, errors.Wrap(err, "failed to deserialize signature")
	}

	hashedPayload, err := Sha256Hash(payload)
	if err != nil {
		return false, err
	}

	return ecdsa.Verify(ecdsaPublicKey, hashedPayload, r, s), nil
}

func Sha256Hash(byts []byte) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(byts)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}
