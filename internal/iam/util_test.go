package iam

import (
	"testing"
)

func TestExtractEmailDomain_Success(t *testing.T) {
	testCases := []struct {
		email          string
		expectedDomain string
	}{
		{"user@example.com", "example.com"},
		{"admin@company.org", "company.org"},
		{"test@subdomain.example.com", "subdomain.example.com"},
		{"user+tag@example.com", "example.com"},
		{"name.surname@example.co.uk", "example.co.uk"},
		{"user@localhost", "localhost"},
	}

	for _, tc := range testCases {
		domain, err := extractEmailDomain(tc.email)
		if err != nil {
			t.Errorf("email %s: expected no error, got %v", tc.email, err)
		}
		if domain != tc.expectedDomain {
			t.Errorf("email %s: expected domain %s, got %s", tc.email, tc.expectedDomain, domain)
		}
	}
}

func TestExtractEmailDomain_MissingAtSymbol(t *testing.T) {
	invalidEmails := []string{
		"userexample.com",
		"plaintext",
		"",
	}

	for _, email := range invalidEmails {
		_, err := extractEmailDomain(email)
		if err == nil {
			t.Errorf("email %s: expected error for missing @ symbol", email)
		}
	}
}

func TestExtractEmailDomain_MissingDomain(t *testing.T) {
	invalidEmails := []string{
		"user@",
		"admin@",
	}

	for _, email := range invalidEmails {
		_, err := extractEmailDomain(email)
		if err == nil {
			t.Errorf("email %s: expected error for missing domain", email)
		}
	}
}

func TestExtractEmailDomain_MultipleAtSymbols(t *testing.T) {
	// Should use the last @ symbol
	email := "user@name@example.com"
	domain, err := extractEmailDomain(email)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %s", domain)
	}
}
