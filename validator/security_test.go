package validator

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestValidateTokenFormat(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		expectErr error
	}{
		{
			name:      "valid JWS token (2 dots)",
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
			expectErr: nil,
		},
		{
			name:      "valid JWE token (4 dots)",
			token:     "header.encrypted_key.iv.ciphertext.tag",
			expectErr: nil,
		},
		{
			name:      "max allowed dots (5)",
			token:     "a.b.c.d.e.f",
			expectErr: nil,
		},
		{
			name:      "excessive dots (6) - CVE-2025-27144",
			token:     "a.b.c.d.e.f.g",
			expectErr: ErrExcessiveTokenDots,
		},
		{
			name:      "many dots (100) - CVE-2025-27144",
			token:     strings.Repeat("a.", 100) + "z",
			expectErr: ErrExcessiveTokenDots,
		},
		{
			name:      "malicious token with 10000 dots",
			token:     strings.Repeat(".", 10000),
			expectErr: ErrExcessiveTokenDots,
		},
		{
			name:      "empty token",
			token:     "",
			expectErr: errors.New("token is empty"),
		},
		{
			name:      "token exceeds 1MB",
			token:     strings.Repeat("a", 1024*1024+1),
			expectErr: errors.New("token exceeds maximum size (1MB)"),
		},
		{
			name:      "token exactly 1MB (allowed)",
			token:     "header." + strings.Repeat("a", 1024*1024-20) + ".sig",
			expectErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTokenFormat(tt.token)
			
			if tt.expectErr == nil {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing '%v', got nil", tt.expectErr)
				} else if !errors.Is(err, tt.expectErr) && !strings.Contains(err.Error(), tt.expectErr.Error()) {
					t.Errorf("expected error '%v', got '%v'", tt.expectErr, err)
				}
			}
		})
	}
}

func TestValidateToken_CVE_2025_27144_Protection(t *testing.T) {
	// This test ensures the CVE-2025-27144 mitigation is in place
	v, err := New(
		func(_ context.Context) (interface{}, error) {
			return []byte("secret"), nil
		},
		HS256,
		"https://issuer.example.com/",
		[]string{"audience"},
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// Test with malicious token containing excessive dots
	maliciousToken := strings.Repeat("a.", 1000) + "z"
	
	_, err = v.ValidateToken(context.Background(), maliciousToken)
	
	if err == nil {
		t.Error("expected error for malicious token, got nil")
	}
	
	if !errors.Is(err, ErrExcessiveTokenDots) && !strings.Contains(err.Error(), "excessive dots") {
		t.Errorf("expected error about excessive dots, got: %v", err)
	}
}

func BenchmarkValidateTokenFormat(b *testing.B) {
	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "normal token",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
		},
		{
			name:  "malicious 100 dots",
			token: strings.Repeat("a.", 100) + "z",
		},
		{
			name:  "malicious 1000 dots",
			token: strings.Repeat("a.", 1000) + "z",
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = validateTokenFormat(tt.token)
			}
		})
	}
}
