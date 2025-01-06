package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/HealthAura/token-service/config"
	tokenservice "github.com/HealthAura/token-service/gen/go/v1"
	"github.com/HealthAura/token-service/internal/domain/tokens"
	"github.com/HealthAura/token-service/internal/endpoint"
	"github.com/HealthAura/token-service/internal/middleware/logging"
	"github.com/HealthAura/token-service/public/jwt"
	"github.com/HealthAura/token-service/public/jwt/tokenstore"
	"github.com/HealthAura/token-service/public/keys"
	mkms "github.com/HealthAura/token-service/public/keys/kms"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

type Application struct {
	Config *config.Config
	Logger *zap.Logger
	router http.Handler
}

func NewApplication(ctx context.Context) (*Application, error) {
	logger, err := zap.NewProduction()
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

	var kmsClient mkms.KMS
	if cfg.Service.DevelopmentMode {
		v, err := base64.RawURLEncoding.DecodeString(cfg.Service.DevelopmentSigningKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode development signing key: %w", err)
		}

		privKey, err := keys.DeserializePrivateKey(v)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize private key: %w", err)
		}

		kmsClient = mkms.NewMock(privKey, false, false)
	} else {
		kmsClient = kms.NewFromConfig(awsConfig)
	}

	var store tokenstore.Store
	if cfg.Service.DevelopmentMode {
		store = tokenstore.NewLocal()
	} else {
		store = tokenstore.New(
			dynamodb.NewFromConfig(awsConfig),
			cfg.TokenStore.DynamoTableName,
		)
	}

	logger.Info("starting token-service", zap.String("signingKey", cfg.Service.SigningKeyARN))
	jwtOrch := jwt.New(kmsClient, cfg.Service.SigningKeyARN, cfg.Service.Issuer, store)
	tokenManager := tokens.New(jwtOrch)

	return &Application{
		router: newRouter(endpoint.New(tokenManager, logger), logger),
		Config: cfg,
		Logger: logger,
	}, nil
}

func newRouter(server tokenservice.ServerInterface, zlog *zap.Logger) http.Handler {
	router := chi.NewRouter()
	router.Use(logging.New(zlog).HTTPMiddleware)
	router.Use(middleware.Recoverer)
	router.Use(middleware.RequestID)

	router.Post("/v1/generate", server.TokenServiceGenerate)
	router.Post("/v1/generate-nonce", server.TokenServiceGenerateNonce)
	router.Post("/v1/refresh", server.TokenServiceRefresh)

	return router
}
