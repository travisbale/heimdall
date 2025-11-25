package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/travisbale/heimdall/internal/iam"
)

func TestRegistrationClient_Discover_Success(t *testing.T) {
	var metadata iam.OIDCDiscoveryMetadata

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}))
	defer server.Close()

	metadata = iam.OIDCDiscoveryMetadata{
		Issuer:                server.URL,
		AuthorizationEndpoint: server.URL + "/authorize",
		TokenEndpoint:         server.URL + "/token",
		JWKSUri:               server.URL + "/jwks",
		UserInfoEndpoint:      server.URL + "/userinfo",
	}

	client := NewRegistrationClient()
	result, err := client.Discover(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.Issuer != metadata.Issuer {
		t.Errorf("issuer = %q, want %q", result.Issuer, metadata.Issuer)
	}
	if result.AuthorizationEndpoint != metadata.AuthorizationEndpoint {
		t.Errorf("authorization_endpoint = %q, want %q", result.AuthorizationEndpoint, metadata.AuthorizationEndpoint)
	}
	if result.TokenEndpoint != metadata.TokenEndpoint {
		t.Errorf("token_endpoint = %q, want %q", result.TokenEndpoint, metadata.TokenEndpoint)
	}
	if result.JWKSUri != metadata.JWKSUri {
		t.Errorf("jwks_uri = %q, want %q", result.JWKSUri, metadata.JWKSUri)
	}
}

func TestRegistrationClient_Discover_TrailingSlash(t *testing.T) {
	// Issuer URL should have trailing slash removed for comparison
	var metadata iam.OIDCDiscoveryMetadata

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}))
	defer server.Close()

	metadata = iam.OIDCDiscoveryMetadata{
		Issuer:                server.URL,
		AuthorizationEndpoint: server.URL + "/authorize",
		TokenEndpoint:         server.URL + "/token",
		JWKSUri:               server.URL + "/jwks",
	}

	client := NewRegistrationClient()
	// Pass URL with trailing slash
	result, err := client.Discover(context.Background(), server.URL+"/")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.Issuer != metadata.Issuer {
		t.Errorf("issuer = %q, want %q", result.Issuer, metadata.Issuer)
	}
}

func TestRegistrationClient_Discover_IssuerMismatch(t *testing.T) {
	// Security test: issuer confusion attack prevention
	metadata := iam.OIDCDiscoveryMetadata{
		Issuer:                "https://evil.example.com",
		AuthorizationEndpoint: "https://evil.example.com/authorize",
		TokenEndpoint:         "https://evil.example.com/token",
		JWKSUri:               "https://evil.example.com/jwks",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}))
	defer server.Close()

	client := NewRegistrationClient()
	_, err := client.Discover(context.Background(), server.URL)

	if err == nil {
		t.Fatal("expected error for issuer mismatch, got nil")
	}

	if !errors.Is(err, iam.ErrOIDCIssuerMismatch) {
		t.Errorf("expected ErrOIDCIssuerMismatch, got: %v", err)
	}
}

func TestRegistrationClient_Discover_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name              string
		omitIssuer        bool
		omitAuthzEndpoint bool
		omitTokenEndpoint bool
		omitJWKS          bool
	}{
		{
			name:       "missing issuer",
			omitIssuer: true,
		},
		{
			name:              "missing authorization_endpoint",
			omitAuthzEndpoint: true,
		},
		{
			name:              "missing token_endpoint",
			omitTokenEndpoint: true,
		},
		{
			name:     "missing jwks_uri",
			omitJWKS: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var metadata iam.OIDCDiscoveryMetadata

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(metadata)
			}))
			defer server.Close()

			// Build metadata based on test case after server is created
			if !tt.omitIssuer {
				metadata.Issuer = server.URL
			}
			if !tt.omitAuthzEndpoint {
				metadata.AuthorizationEndpoint = server.URL + "/authorize"
			}
			if !tt.omitTokenEndpoint {
				metadata.TokenEndpoint = server.URL + "/token"
			}
			if !tt.omitJWKS {
				metadata.JWKSUri = server.URL + "/jwks"
			}

			client := NewRegistrationClient()
			_, err := client.Discover(context.Background(), server.URL)

			if err == nil {
				t.Error("expected error, got nil")
			}
			if err != nil && !errors.Is(err, iam.ErrOIDCDiscoveryFailed) && !errors.Is(err, iam.ErrOIDCIssuerMismatch) {
				t.Errorf("expected discovery or issuer mismatch error, got: %v", err)
			}
		})
	}
}

func TestRegistrationClient_Discover_HTTPErrors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{"not found", http.StatusNotFound, true},
		{"server error", http.StatusInternalServerError, true},
		{"unauthorized", http.StatusUnauthorized, true},
		{"success", http.StatusOK, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var serverURL string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.statusCode == http.StatusOK {
					metadata := iam.OIDCDiscoveryMetadata{
						Issuer:                serverURL,
						AuthorizationEndpoint: serverURL + "/authorize",
						TokenEndpoint:         serverURL + "/token",
						JWKSUri:               serverURL + "/jwks",
					}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(metadata)
				} else {
					w.WriteHeader(tt.statusCode)
					w.Write([]byte("error message"))
				}
			}))
			defer server.Close()
			serverURL = server.URL

			client := NewRegistrationClient()
			_, err := client.Discover(context.Background(), server.URL)

			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

func TestRegistrationClient_Discover_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not valid json{"))
	}))
	defer server.Close()

	client := NewRegistrationClient()
	_, err := client.Discover(context.Background(), server.URL)

	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}

	if !errors.Is(err, iam.ErrOIDCDiscoveryFailed) {
		t.Errorf("expected ErrOIDCDiscoveryFailed, got: %v", err)
	}
}

func TestRegistrationClient_Register_Success(t *testing.T) {
	registration := iam.OIDCRegistration{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", contentType)
		}

		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(registration)
	}))
	defer server.Close()

	client := NewRegistrationClient()
	result, err := client.Register(
		context.Background(),
		server.URL,
		"https://example.com/callback",
		"Test Client",
		"",
		[]string{"openid", "email"},
	)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.ClientID != registration.ClientID {
		t.Errorf("client_id = %q, want %q", result.ClientID, registration.ClientID)
	}
	if result.ClientSecret != registration.ClientSecret {
		t.Errorf("client_secret = %q, want %q", result.ClientSecret, registration.ClientSecret)
	}
}

func TestRegistrationClient_Register_WithAccessToken(t *testing.T) {
	registration := iam.OIDCRegistration{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	accessToken := "bearer-token-123"
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(registration)
	}))
	defer server.Close()

	client := NewRegistrationClient()
	_, err := client.Register(
		context.Background(),
		server.URL,
		"https://example.com/callback",
		"Test Client",
		accessToken,
		[]string{"openid"},
	)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	expectedAuth := "Bearer " + accessToken
	if receivedAuth != expectedAuth {
		t.Errorf("Authorization header = %q, want %q", receivedAuth, expectedAuth)
	}
}

func TestRegistrationClient_Register_EmptyEndpoint(t *testing.T) {
	client := NewRegistrationClient()
	_, err := client.Register(
		context.Background(),
		"",
		"https://example.com/callback",
		"Test Client",
		"",
		[]string{"openid"},
	)

	if err == nil {
		t.Fatal("expected error for empty registration endpoint, got nil")
	}

	if !errors.Is(err, iam.ErrOIDCRegistrationFailed) {
		t.Errorf("expected ErrOIDCRegistrationFailed, got: %v", err)
	}
}

func TestRegistrationClient_Register_MissingCredentials(t *testing.T) {
	tests := []struct {
		name         string
		registration iam.OIDCRegistration
	}{
		{
			name: "missing client_id",
			registration: iam.OIDCRegistration{
				ClientSecret: "test-secret",
			},
		},
		{
			name: "missing client_secret",
			registration: iam.OIDCRegistration{
				ClientID: "test-id",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tt.registration)
			}))
			defer server.Close()

			client := NewRegistrationClient()
			_, err := client.Register(
				context.Background(),
				server.URL,
				"https://example.com/callback",
				"Test Client",
				"",
				[]string{"openid"},
			)

			if err == nil {
				t.Fatal("expected error for missing credentials, got nil")
			}

			if !errors.Is(err, iam.ErrOIDCRegistrationFailed) {
				t.Errorf("expected ErrOIDCRegistrationFailed, got: %v", err)
			}
		})
	}
}

func TestRegistrationClient_Register_RFC7592_Compliance(t *testing.T) {
	tests := []struct {
		name         string
		registration iam.OIDCRegistration
		wantErr      bool
	}{
		{
			name: "both token and URI present (valid)",
			registration: iam.OIDCRegistration{
				ClientID:                "test-id",
				ClientSecret:            "test-secret",
				RegistrationAccessToken: "token",
				RegistrationClientURI:   "https://provider.example.com/register/client-id",
			},
			wantErr: false,
		},
		{
			name: "neither token nor URI present (valid)",
			registration: iam.OIDCRegistration{
				ClientID:     "test-id",
				ClientSecret: "test-secret",
			},
			wantErr: false,
		},
		{
			name: "token without URI (invalid)",
			registration: iam.OIDCRegistration{
				ClientID:                "test-id",
				ClientSecret:            "test-secret",
				RegistrationAccessToken: "token",
			},
			wantErr: true,
		},
		{
			name: "URI without token (invalid)",
			registration: iam.OIDCRegistration{
				ClientID:              "test-id",
				ClientSecret:          "test-secret",
				RegistrationClientURI: "https://provider.example.com/register/client-id",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tt.registration)
			}))
			defer server.Close()

			client := NewRegistrationClient()
			_, err := client.Register(
				context.Background(),
				server.URL,
				"https://example.com/callback",
				"Test Client",
				"",
				[]string{"openid"},
			)

			if tt.wantErr && err == nil {
				t.Error("expected error for RFC 7592 violation, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

func TestRegistrationClient_Register_HTTPErrors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"bad request", http.StatusBadRequest},
		{"unauthorized", http.StatusUnauthorized},
		{"forbidden", http.StatusForbidden},
		{"server error", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte("error message"))
			}))
			defer server.Close()

			client := NewRegistrationClient()
			_, err := client.Register(
				context.Background(),
				server.URL,
				"https://example.com/callback",
				"Test Client",
				"",
				[]string{"openid"},
			)

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, iam.ErrOIDCRegistrationFailed) {
				t.Errorf("expected ErrOIDCRegistrationFailed, got: %v", err)
			}
		})
	}
}

func TestRegistrationClient_Unregister_Success(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"no content", http.StatusNoContent},
		{"not found (idempotent)", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("expected DELETE, got %s", r.Method)
				}

				auth := r.Header.Get("Authorization")
				if auth != "Bearer test-token" {
					t.Errorf("expected Bearer token, got %s", auth)
				}

				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			client := NewRegistrationClient()
			err := client.Unregister(
				context.Background(),
				server.URL,
				"test-token",
			)

			if err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

func TestRegistrationClient_Unregister_EmptyURI(t *testing.T) {
	// Empty URI should be no-op (no client to unregister)
	client := NewRegistrationClient()
	err := client.Unregister(context.Background(), "", "test-token")

	if err != nil {
		t.Errorf("expected no error for empty URI, got: %v", err)
	}
}

func TestRegistrationClient_Unregister_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	client := NewRegistrationClient()
	err := client.Unregister(
		context.Background(),
		server.URL,
		"test-token",
	)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
