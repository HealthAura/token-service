package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/HealthAura/token-service/public/keys"
)

type key struct {
	PrivateKey string
	PublicKey  string
}

func main() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("Failed to generate private key.")
	}

	privateKeySerialized, err := keys.SerializePrivateKey(privateKey)
	if err != nil {
		log.Fatal("Failed to serialize private key.")
	}

	publicKeySerialized := keys.SerializePublicKey(&privateKey.PublicKey)

	encodedKey := key{
		PrivateKey: base64.RawURLEncoding.EncodeToString(privateKeySerialized),
		PublicKey:  base64.RawURLEncoding.EncodeToString(publicKeySerialized),
	}

	v, err := json.MarshalIndent(encodedKey, "", "    ")
	if err != nil {
		log.Fatal("Failed to marshal key.")
	}

	fmt.Println(string(v))
}
