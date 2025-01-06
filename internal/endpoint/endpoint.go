package endpoint

import (
	"encoding/json"
	"io"
	"net/http"

	tokenservice "github.com/HealthAura/token-service/gen/go/v1"
	"github.com/HealthAura/token-service/internal/domain/tokens"
	"go.uber.org/zap"
)

type TokenServiceServer struct {
	tokenManager tokens.Manager
	zlog         *zap.Logger
}

func New(tokenManager tokens.Manager, zlog *zap.Logger) tokenservice.ServerInterface {
	return &TokenServiceServer{
		tokenManager: tokenManager,
		zlog:         zlog,
	}
}

// Generate creates a new access token and refresh token based on the provided claims and DPoP proof.
// (POST /v1/generate)
func (t TokenServiceServer) TokenServiceGenerate(w http.ResponseWriter, r *http.Request) {
	v, err := io.ReadAll(r.Body)
	if err != nil {
		t.zlog.Error("failed to read request body", zap.Error(err))
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	var req tokenservice.TokenserviceGenerateRequest
	if err := json.Unmarshal(v, &req); err != nil {
		t.zlog.Error("failed to unmarshal request body", zap.Error(err))
		http.Error(w, "failed to unmarshal request body", http.StatusBadRequest)
		return
	}

	resp, err := t.tokenManager.Generate(r.Context(), &req)
	if err != nil {
		t.zlog.Error("failed to generate token", zap.Error(err))
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	v, err = json.Marshal(resp)
	if err != nil {
		t.zlog.Error("failed to marshal response", zap.Error(err))
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}

	_, err = w.Write(v)
	if err != nil {
		t.zlog.Error("failed to write response", zap.Error(err))
		http.Error(w, "failed to write response", http.StatusInternalServerError)
		return
	}
}

// GenerateNonce creates a new nonce based on the provided claims.
// (POST /v1/generate-nonce)
func (t TokenServiceServer) TokenServiceGenerateNonce(w http.ResponseWriter, r *http.Request) {
	v, err := io.ReadAll(r.Body)
	if err != nil {
		t.zlog.Error("failed to read request body", zap.Error(err))
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	var req tokenservice.TokenserviceGenerateNonceRequest
	if err := json.Unmarshal(v, &req); err != nil {
		t.zlog.Error("failed to unmarshal request body", zap.Error(err))
		http.Error(w, "failed to unmarshal request body", http.StatusBadRequest)
		return
	}

	resp, err := t.tokenManager.GenerateNonce(r.Context(), &req)
	if err != nil {
		t.zlog.Error("failed to generate token", zap.Error(err))
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	v, err = json.Marshal(resp)
	if err != nil {
		t.zlog.Error("failed to marshal response", zap.Error(err))
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}

	_, err = w.Write(v)
	if err != nil {
		t.zlog.Error("failed to write response", zap.Error(err))
		http.Error(w, "failed to write response", http.StatusInternalServerError)
		return
	}
}

// Refresh generates a new access token and refresh token using the provided refresh token and DPoP proof.
// (POST /v1/refresh)
func (t TokenServiceServer) TokenServiceRefresh(w http.ResponseWriter, r *http.Request) {
	v, err := io.ReadAll(r.Body)
	if err != nil {
		t.zlog.Error("failed to read request body", zap.Error(err))
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	var req tokenservice.TokenserviceRefreshRequest
	if err := json.Unmarshal(v, &req); err != nil {
		t.zlog.Error("failed to unmarshal request body", zap.Error(err))
		http.Error(w, "failed to unmarshal request body", http.StatusBadRequest)
		return
	}

	resp, err := t.tokenManager.Refresh(r.Context(), &req)
	if err != nil {
		t.zlog.Error("failed to generate token", zap.Error(err))
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	v, err = json.Marshal(resp)
	if err != nil {
		t.zlog.Error("failed to marshal response", zap.Error(err))
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}

	_, err = w.Write(v)
	if err != nil {
		t.zlog.Error("failed to write response", zap.Error(err))
		http.Error(w, "failed to write response", http.StatusInternalServerError)
		return
	}
}
