package config

import (
	"fmt"

	"github.com/caarlos0/env/v6"
)

type Config struct {
	Service    Service
	TokenStore TokenStore
}

type Service struct {
	AWSRegion             string `env:"TOKEN_SERVICE_AWS_REGION" envDefault:"us-east-1"`
	DevelopmentMode       bool   `env:"TOKEN_SERVICE_DEVELOPMENT_MODE"`
	DevelopmentSigningKey string `env:"TOKEN_SERVICE_DEVELOPMENT_SIGNING_KEY"`

	SigningKeyARN string `env:"TOKEN_SERVICE_SIGNING_KEY_ARN"`
	Issuer        string `env:"TOKEN_SERVICE_ISSUER"`
}

type TokenStore struct {
	DynamoTableName string `env:"TOKEN_SERVICE_DYNAMO_TABLE_NAME"`
}

func Load() (*Config, error) {
	cfg := Config{}
	if err := env.Parse(&cfg); err != nil {
		return &cfg, fmt.Errorf("failed to load environment: %s", err.Error())
	}

	return &cfg, nil
}
