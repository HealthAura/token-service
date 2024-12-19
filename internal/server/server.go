package server

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/HealthAura/token-service/config"
	"github.com/HealthAura/token-service/internal/domain/tokens"
	"github.com/HealthAura/token-service/public/jwt"
	"github.com/HealthAura/token-service/public/jwt/tokenstore"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/go-redis/redis"
	"go.uber.org/zap"
)

type Application struct {
	TokenManager tokens.Manager
	Config       *config.Config
	Logger       *zap.Logger
}

func NewApplication(ctx context.Context) (*Application, error) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Service.AWSRegion))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	kmsClient := kms.NewFromConfig(awsConfig)

	store, err := initializeTokenStore(cfg, awsConfig, kmsClient, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize token store: %w", err)
	}

	jwtOrch := jwt.New(kmsClient, cfg.Service.SigningKeyARN, cfg.Service.Issuer, store)
	return &Application{
		TokenManager: tokens.New(jwtOrch),
		Config:       cfg,
		Logger:       logger,
	}, nil
}

func initializeTokenStore(cfg *config.Config, awsConfig aws.Config, kmsClient *kms.Client, logger *zap.Logger) (tokenstore.Store, error) {
	if cfg.TokenStore.DynamoDB {
		client := dynamodb.NewFromConfig(awsConfig)
		return tokenstore.NewDynamo(
			client,
			kmsClient,
			cfg.TokenStore.DynamoTableName,
			cfg.TokenStore.DynamoKeyID,
		), nil
	}

	var redisClient *redis.Client
	if cfg.Service.DevelopmentMode {
		redisClient = redis.NewClient(&redis.Options{
			Addr: cfg.TokenStore.RedisURL,
			DB:   0,
		})
	} else {
		redisClient = redis.NewClient(&redis.Options{
			Addr:      cfg.TokenStore.RedisURL,
			DB:        0,
			TLSConfig: &tls.Config{},
		})
	}

	if _, err := redisClient.Ping().Result(); err != nil {
		logger.With(
			zap.String("error", err.Error()),
			zap.String("redis_url", cfg.TokenStore.RedisURL),
		).Info("failed to ping redis db")
	}

	return tokenstore.NewRedis(
		redisClient,
		kmsClient,
		cfg.Service.DatabaseKeyARN,
	), nil
}
