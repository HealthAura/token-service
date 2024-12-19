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
	IsGRPC                bool   `env:"TOKEN_SERVICE_IS_GRPC" envDefault:"false"`
	Port                  int    `env:"TOKEN_SERVICE_PORT" envDefault:"8080"`
	ListenAddress         string `env:"TOKEN_SERVICE_LISTEN_ADDRESS" envDefault:"0.0.0.0"`
	DevelopmentMode       bool   `env:"TOKEN_SERVICE_DEVELOPMENT_MODE"`
	DevelopmentSigningKey string `env:"TOKEN_SERVICE_DEVELOPMENT_SIGNING_KEY"`

	SigningKeyARN  string `env:"TOKEN_SERVICE_SIGNING_KEY_ARN"`
	DatabaseKeyARN string `env:"TOKEN_SERVICE_KMS_DATABASE_KEY_ARN"`
	Issuer         string `env:"TOKEN_SERVICE_ISSUER"`
	TestURI        string `env:"TOKEN_SERVICE_TEST_URI" envDefault:"127.0.0.1:8081"`
}

type TokenStore struct {
	RedisURL        string `env:"TOKEN_SERVICE_REDIS_URL"`
	DynamoDB        bool   `env:"true"`
	DynamoTableName string `env:"TOKEN_SERVICE_DYNAMO_TABLE_NAME"`
	DynamoKeyID     string `env:"TOKEN_SERVICE_DYNAMO_KEY_ID"`
}

func Load() (*Config, error) {
	cfg := Config{}
	if err := env.Parse(&cfg); err != nil {
		return &cfg, fmt.Errorf("failed to load environment: %s", err.Error())
	}

	return &cfg, nil
}
