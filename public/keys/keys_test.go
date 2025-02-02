package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignAndVerifyUnit(t *testing.T) {
	testPayload := []byte("Test Payload")

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	signature, err := Sign(privKey, testPayload)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	serializedPublicKey := SerializePublicKey(&privKey.PublicKey)
	ok, err := Verify(serializedPublicKey, testPayload, signature)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	assert.True(t, ok)
}

func TestPublicKeySerializationUnit(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	serializedPublicKey := SerializePublicKey(&privKey.PublicKey)
	desrializedPublicKey, err := DeserializePublicKey(serializedPublicKey)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	serializedPublicKey2 := SerializePublicKey(desrializedPublicKey)

	assert.Equal(t, serializedPublicKey, serializedPublicKey2)
}

func TestSignatureSerializationUnit(t *testing.T) {
	testPayload := []byte("Test Payload")

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	serializedSignature, err := Sign(privKey, testPayload)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	r, s, err := DeserializeSignature(serializedSignature)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	serializedSignature2, err := SerializeSignature(r, s)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	assert.Equal(t, serializedSignature, serializedSignature2)
}

func TestPrivateKeySerializationUnit(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	v, err := SerializePrivateKey(privKey)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	deserializedPrivateKey, err := DeserializePrivateKey(v)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	v2, err := SerializePrivateKey(deserializedPrivateKey)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	assert.Equal(t, v, v2)
}
