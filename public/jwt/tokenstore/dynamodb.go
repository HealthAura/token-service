package tokenstore

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/HealthAura/token-service/public/keys"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type TokenItem struct {
	SignatureHash string `dynamodbav:"signature_hash"`
	TokenData     []byte `dynamodbav:"token_data"`
	ExpiresAt     int64  `dynamodbav:"expires_at"`
	ATH           string `dynamodbav:"ath,omitempty"`
}

type dynamoStore struct {
	dynamoClient *dynamodb.Client
	tableName    string
}

func New(dynamoClient *dynamodb.Client, tableName string) Store {
	return dynamoStore{
		dynamoClient: dynamoClient,
		tableName:    tableName,
	}
}

func (s dynamoStore) StoreToken(ctx context.Context, jwtToken string, ttl time.Duration) error {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	tokenWithoutSignature := parts[0] + "." + parts[1]
	signature := parts[2]
	signatureHash, err := keys.Sha256Hash([]byte(signature))
	if err != nil {
		return fmt.Errorf("failed to hash signature: %w", err)
	}

	item := TokenItem{
		SignatureHash: base64.RawURLEncoding.EncodeToString(signatureHash),
		TokenData:     []byte(tokenWithoutSignature),
		ExpiresAt:     time.Now().Add(ttl).Unix(),
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("failed to marshal token item: %w", err)
	}

	_, err = s.dynamoClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      av,
	})
	if err != nil {
		return fmt.Errorf("failed to store token in dynamodb: %w", err)
	}

	return nil
}

func (s dynamoStore) GetToken(ctx context.Context, signature string) (string, error) {
	signatureHash, err := keys.Sha256Hash([]byte(signature))
	if err != nil {
		return "", fmt.Errorf("failed to hash signature: %w", err)
	}

	key, err := attributevalue.MarshalMap(map[string]string{
		"signature_hash": base64.RawURLEncoding.EncodeToString(signatureHash),
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal key: %w", err)
	}

	result, err := s.dynamoClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key:       key,
	})

	if err != nil {
		return "", fmt.Errorf("failed to get token from dynamodb: %w", err)
	}

	if result.Item == nil {
		return "", NotFoundErr{}
	}

	var item TokenItem
	if err := attributevalue.UnmarshalMap(result.Item, &item); err != nil {
		return "", fmt.Errorf("failed to unmarshal token item: %w", err)
	}

	if item.ExpiresAt < time.Now().Unix() {
		return "", NotFoundErr{}
	}

	splitToken := string(item.TokenData)

	return fmt.Sprintf("%s.%s", splitToken, signature), nil
}

func (s dynamoStore) DeleteToken(ctx context.Context, signature string) error {
	signatureHash, err := keys.Sha256Hash([]byte(signature))
	if err != nil {
		return fmt.Errorf("failed to hash signature: %w", err)
	}

	key, err := attributevalue.MarshalMap(map[string]string{
		"signature_hash": base64.RawURLEncoding.EncodeToString(signatureHash),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	_, err = s.dynamoClient.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.tableName),
		Key:       key,
	})

	if err != nil {
		return fmt.Errorf("failed to delete token from dynamodb: %w", err)
	}

	return nil
}

func (s dynamoStore) DeleteTokenByATH(ctx context.Context, ath string) error {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		IndexName:              aws.String("ath-index"),
		KeyConditionExpression: aws.String("ath = :ath"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ath": &types.AttributeValueMemberS{Value: ath},
		},
	}

	result, err := s.dynamoClient.Query(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to query token by ATH: %w", err)
	}

	if len(result.Items) == 0 {
		return NotFoundErr{}
	}

	// Delete the found item
	var item TokenItem
	if err := attributevalue.UnmarshalMap(result.Items[0], &item); err != nil {
		return fmt.Errorf("failed to unmarshal token item: %w", err)
	}

	key, err := attributevalue.MarshalMap(map[string]string{
		"signature_hash": item.SignatureHash,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	_, err = s.dynamoClient.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.tableName),
		Key:       key,
	})

	if err != nil {
		return fmt.Errorf("failed to delete token from dynamodb: %w", err)
	}

	return nil
}
