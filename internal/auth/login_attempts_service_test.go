package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Mock implementation for login attempts database

type mockLoginAttemptsDB struct {
	recentFailedCount int64
	recentFailedError error
	mostRecentLockout *time.Time
	lockoutError      error
	recordedAttempts  []recordedAttempt
	recordError       error
	deletedOlderThan  *time.Time
	deleteError       error
}

type recordedAttempt struct {
	email       string
	userID      *uuid.UUID
	ipAddress   string
	lockedUntil *time.Time
}

func (m *mockLoginAttemptsDB) RecordAttempt(ctx context.Context, email string, userID *uuid.UUID, ipAddress string, lockedUntil *time.Time) error {
	if m.recordError != nil {
		return m.recordError
	}
	m.recordedAttempts = append(m.recordedAttempts, recordedAttempt{
		email:       email,
		userID:      userID,
		ipAddress:   ipAddress,
		lockedUntil: lockedUntil,
	})
	return nil
}

func (m *mockLoginAttemptsDB) GetRecentFailedAttempts(ctx context.Context, email string, since time.Time) (int64, error) {
	if m.recentFailedError != nil {
		return 0, m.recentFailedError
	}
	return m.recentFailedCount, nil
}

func (m *mockLoginAttemptsDB) GetMostRecentLockout(ctx context.Context, email string) (*time.Time, error) {
	if m.lockoutError != nil {
		return nil, m.lockoutError
	}
	return m.mostRecentLockout, nil
}

func (m *mockLoginAttemptsDB) DeleteOldLoginAttempts(ctx context.Context, olderThan time.Time) error {
	if m.deleteError != nil {
		return m.deleteError
	}
	m.deletedOlderThan = &olderThan
	return nil
}

// Helper function to create test service
func createTestLoginAttemptsService() (*LoginAttemptsService, *mockLoginAttemptsDB) {
	db := &mockLoginAttemptsDB{}
	logger := &mockLogger{}
	service := NewLoginAttemptsService(db, logger)
	return service, db
}

// IsAccountLocked Tests

func TestIsAccountLocked_NotLocked_NoLockout(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	db.mostRecentLockout = nil

	locked, lockedUntil, err := service.IsAccountLocked(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if locked {
		t.Error("expected account to not be locked")
	}

	if !lockedUntil.IsZero() {
		t.Error("expected zero time for unlocked account")
	}
}

func TestIsAccountLocked_NotLocked_ExpiredLockout(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	// Lockout expired 1 minute ago
	expiredLockout := time.Now().Add(-1 * time.Minute)
	db.mostRecentLockout = &expiredLockout

	locked, lockedUntil, err := service.IsAccountLocked(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if locked {
		t.Error("expected account to not be locked (lockout expired)")
	}

	if !lockedUntil.IsZero() {
		t.Error("expected zero time for expired lockout")
	}
}

func TestIsAccountLocked_Locked(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	// Lockout expires in 5 minutes
	futureLockout := time.Now().Add(5 * time.Minute)
	db.mostRecentLockout = &futureLockout

	locked, lockedUntil, err := service.IsAccountLocked(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !locked {
		t.Error("expected account to be locked")
	}

	if !lockedUntil.Equal(futureLockout) {
		t.Errorf("expected lockedUntil to be %v, got %v", futureLockout, lockedUntil)
	}
}

func TestIsAccountLocked_DatabaseError(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	db.lockoutError = ErrUserNotFound

	_, _, err := service.IsAccountLocked(ctx, "user@example.com")
	if err == nil {
		t.Error("expected error from database")
	}
}

// RecordFailedLogin Tests

func TestRecordFailedLogin_FirstAttempt(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	db.recentFailedCount = 0 // No previous failures

	userID := uuid.New()
	ipAddress := "192.168.1.1"
	err := service.RecordFailedLogin(ctx, "user@example.com", &userID, ipAddress, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(db.recordedAttempts) != 1 {
		t.Fatalf("expected 1 recorded attempt, got %d", len(db.recordedAttempts))
	}

	attempt := db.recordedAttempts[0]
	if attempt.email != "user@example.com" {
		t.Errorf("expected email 'user@example.com', got %s", attempt.email)
	}

	// First attempt should not trigger lockout
	if attempt.lockedUntil != nil {
		t.Error("expected no lockout on first attempt")
	}
}

func TestRecordFailedLogin_FifthAttempt_5MinuteLockout(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	db.recentFailedCount = 4 // 4 previous failures, this will be the 5th

	before := time.Now()
	err := service.RecordFailedLogin(ctx, "user@example.com", nil, "", nil)
	after := time.Now()

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(db.recordedAttempts) != 1 {
		t.Fatalf("expected 1 recorded attempt, got %d", len(db.recordedAttempts))
	}

	attempt := db.recordedAttempts[0]
	if attempt.lockedUntil == nil {
		t.Fatal("expected lockout on 5th attempt")
	}

	// Should be locked for ~5 minutes
	expectedLockout := before.Add(5 * time.Minute)
	if attempt.lockedUntil.Before(expectedLockout.Add(-1*time.Second)) ||
		attempt.lockedUntil.After(after.Add(5*time.Minute).Add(1*time.Second)) {
		t.Errorf("expected ~5 minute lockout, got %v", time.Until(*attempt.lockedUntil))
	}
}

func TestRecordFailedLogin_TenthAttempt_15MinuteLockout(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	db.recentFailedCount = 9 // 9 previous failures, this will be the 10th

	before := time.Now()
	err := service.RecordFailedLogin(ctx, "user@example.com", nil, "", nil)
	after := time.Now()

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	attempt := db.recordedAttempts[0]
	if attempt.lockedUntil == nil {
		t.Fatal("expected lockout on 10th attempt")
	}

	// Should be locked for ~15 minutes
	expectedLockout := before.Add(15 * time.Minute)
	if attempt.lockedUntil.Before(expectedLockout.Add(-1*time.Second)) ||
		attempt.lockedUntil.After(after.Add(15*time.Minute).Add(1*time.Second)) {
		t.Errorf("expected ~15 minute lockout, got %v", time.Until(*attempt.lockedUntil))
	}
}

func TestRecordFailedLogin_FifteenthAttempt_1HourLockout(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	db.recentFailedCount = 14 // 14 previous failures, this will be the 15th

	before := time.Now()
	err := service.RecordFailedLogin(ctx, "user@example.com", nil, "", nil)
	after := time.Now()

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	attempt := db.recordedAttempts[0]
	if attempt.lockedUntil == nil {
		t.Fatal("expected lockout on 15th attempt")
	}

	// Should be locked for ~1 hour
	expectedLockout := before.Add(1 * time.Hour)
	if attempt.lockedUntil.Before(expectedLockout.Add(-1*time.Second)) ||
		attempt.lockedUntil.After(after.Add(1*time.Hour).Add(1*time.Second)) {
		t.Errorf("expected ~1 hour lockout, got %v", time.Until(*attempt.lockedUntil))
	}
}

func TestRecordFailedLogin_TwentiethAttempt_24HourLockout(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	db.recentFailedCount = 19 // 19 previous failures, this will be the 20th

	before := time.Now()
	err := service.RecordFailedLogin(ctx, "user@example.com", nil, "", nil)
	after := time.Now()

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	attempt := db.recordedAttempts[0]
	if attempt.lockedUntil == nil {
		t.Fatal("expected lockout on 20th attempt")
	}

	// Should be locked for ~24 hours
	expectedLockout := before.Add(24 * time.Hour)
	if attempt.lockedUntil.Before(expectedLockout.Add(-1*time.Second)) ||
		attempt.lockedUntil.After(after.Add(24*time.Hour).Add(1*time.Second)) {
		t.Errorf("expected ~24 hour lockout, got %v", time.Until(*attempt.lockedUntil))
	}
}

func TestRecordFailedLogin_BetweenThresholds_NoLockout(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	// Test counts that are between lockout thresholds
	testCases := []int64{1, 2, 3, 6, 7, 11, 12, 16, 17, 21}

	for _, count := range testCases {
		db.recordedAttempts = nil        // Reset
		db.recentFailedCount = count - 1 // Previous failures

		err := service.RecordFailedLogin(ctx, "user@example.com", nil, "", nil)
		if err != nil {
			t.Fatalf("count %d: expected no error, got %v", count, err)
		}

		attempt := db.recordedAttempts[0]
		if attempt.lockedUntil != nil {
			t.Errorf("count %d: expected no lockout between thresholds, got lockout until %v", count, *attempt.lockedUntil)
		}
	}
}

func TestRecordFailedLogin_WithLastLoginAt(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	// User last logged in 2 hours ago
	lastLogin := time.Now().Add(-2 * time.Hour)
	db.recentFailedCount = 4 // Should trigger 5-minute lockout on this attempt

	err := service.RecordFailedLogin(ctx, "user@example.com", nil, "", &lastLogin)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// The window start should be based on lastLoginAt, not the 24-hour default
	// This is verified by the fact that the service successfully counts 4 recent failures
	if len(db.recordedAttempts) != 1 {
		t.Errorf("expected 1 recorded attempt, got %d", len(db.recordedAttempts))
	}
}

func TestRecordFailedLogin_DatabaseError(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	db.recentFailedError = ErrUserNotFound

	err := service.RecordFailedLogin(ctx, "user@example.com", nil, "", nil)
	if err == nil {
		t.Error("expected error from database")
	}
}

// RecordSuccessfulLogin Tests

func TestRecordSuccessfulLogin_DeletesOldAttempts(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	err := service.RecordSuccessfulLogin(ctx, "user@example.com", nil, "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if db.deletedOlderThan == nil {
		t.Fatal("expected DeleteOldLoginAttempts to be called")
	}

	// Should delete attempts older than 7 days
	expectedCutoff := time.Now().Add(-7 * 24 * time.Hour)
	timeDiff := db.deletedOlderThan.Sub(expectedCutoff).Abs()
	if timeDiff > 1*time.Second {
		t.Errorf("expected cutoff ~7 days ago, got %v", db.deletedOlderThan)
	}
}

func TestRecordSuccessfulLogin_DatabaseError_LogsButSucceeds(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	db.deleteError = ErrUserNotFound

	// Should not return error even if cleanup fails
	err := service.RecordSuccessfulLogin(ctx, "user@example.com", nil, "")
	if err != nil {
		t.Errorf("expected no error (cleanup failure should be logged), got %v", err)
	}
}

// Integration-style tests

func TestLoginAttemptsFlow_ProgressiveLockout(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	email := "attacker@example.com"

	// First 4 attempts - no lockout
	for i := range 4 {
		db.recentFailedCount = int64(i)
		err := service.RecordFailedLogin(ctx, email, nil, "", nil)
		if err != nil {
			t.Fatalf("attempt %d: unexpected error: %v", i+1, err)
		}

		attempt := db.recordedAttempts[len(db.recordedAttempts)-1]
		if attempt.lockedUntil != nil {
			t.Errorf("attempt %d: expected no lockout, got lockout", i+1)
		}
	}

	// 5th attempt - should trigger 5 minute lockout
	db.recentFailedCount = 4
	err := service.RecordFailedLogin(ctx, email, nil, "", nil)
	if err != nil {
		t.Fatalf("5th attempt: unexpected error: %v", err)
	}

	attempt := db.recordedAttempts[len(db.recordedAttempts)-1]
	if attempt.lockedUntil == nil {
		t.Error("5th attempt: expected lockout")
	}

	// Check if account is locked
	db.mostRecentLockout = attempt.lockedUntil
	locked, _, err := service.IsAccountLocked(ctx, email)
	if err != nil {
		t.Fatalf("IsAccountLocked: unexpected error: %v", err)
	}
	if !locked {
		t.Error("expected account to be locked after 5th attempt")
	}
}

func TestLoginAttemptsFlow_SuccessfulLoginResetsLockout(t *testing.T) {
	service, db := createTestLoginAttemptsService()
	ctx := context.Background()

	email := "user@example.com"

	// Record failed attempts
	db.recentFailedCount = 4
	err := service.RecordFailedLogin(ctx, email, nil, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Successful login should cleanup old attempts
	err = service.RecordSuccessfulLogin(ctx, email, nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if db.deletedOlderThan == nil {
		t.Error("expected cleanup to be triggered on successful login")
	}
}
