package metadata

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

type key string

const (
	metadataKey   key = "token-service-metadata"
	UserAgentKey  key = "user-agent"
	CorrelationID key = "x-correlation-id"
)

type Metadata struct {
	ClientIP      string
	UserAgent     string
	Method        string
	CorrelationID string
}

func Get(ctx context.Context) Metadata {
	md, ok := ctx.Value(metadataKey).(Metadata)
	if !ok {
		return Metadata{}
	}

	return md
}

func Set(md Metadata, ctx context.Context) context.Context {
	return context.WithValue(ctx, metadataKey, md)
}

func Load(ctx context.Context, method string) context.Context {
	structuredMD := Metadata{
		Method: method,
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return Set(structuredMD, ctx)
	}

	userAgents := md.Get(string(UserAgentKey))
	if len(userAgents) > 0 {
		structuredMD.UserAgent = userAgents[0]
	}

	p, ok := peer.FromContext(ctx)
	if ok {
		structuredMD.ClientIP = p.Addr.String()
	}

	if correlationIDs := md.Get(string(CorrelationID)); len(correlationIDs) > 0 {
		structuredMD.CorrelationID = correlationIDs[0]
	} else {
		structuredMD.CorrelationID = uuid.NewString()
	}

	return Set(structuredMD, ctx)
}
