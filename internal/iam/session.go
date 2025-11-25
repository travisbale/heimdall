package iam

import "time"

// SessionTokens contains all tokens issued for a user session
type SessionTokens struct {
	AccessToken            string
	RefreshToken           string
	MFAChallengeToken      string
	MFASetupToken          string
	AccessExpiration       time.Duration
	RefreshExpiration      time.Duration
	MFAChallengeExpiration time.Duration
	MFASetupExpiration     time.Duration
}

// RequiresMFA returns true if MFA verification is needed to complete authentication
func (s *SessionTokens) RequiresMFA() bool {
	return s.MFAChallengeToken != ""
}

// RequiresMFASetup returns true if user must set up MFA before getting full access
func (s *SessionTokens) RequiresMFASetup() bool {
	return s.MFASetupToken != ""
}
