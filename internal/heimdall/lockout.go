package heimdall

import (
	"errors"
	"time"
)

type LoginAttempt struct {
	UserID     int
	Successful bool
	Timestamp  time.Time
}

type loginAttemptService interface {
	GetRecentAttempts(userID, count int) ([]*LoginAttempt, error)
	SaveAttempt(userID int, attempt *LoginAttempt) error
}

type LockoutService struct {
	maxLoginAttempts    int
	lockoutDuration     time.Duration
	loginAttemptService loginAttemptService
}

var ErrUserLockedOut = errors.New("user is locked out")

func NewLockoutService(maxLoginAttempts int, lockoutDuration time.Duration, loginAttemptService loginAttemptService) *LockoutService {
	return &LockoutService{
		maxLoginAttempts:    maxLoginAttempts,
		lockoutDuration:     lockoutDuration,
		loginAttemptService: loginAttemptService,
	}
}

func (s *LockoutService) CanLogin(userID int) error {
	attempts, err := s.loginAttemptService.GetRecentAttempts(userID, s.maxLoginAttempts)
	if err != nil {
		return err
	}

	if len(attempts) > 0 {
		return nil
	}

	for _, attempt := range attempts {
		if attempt.Successful {
			return nil
		}
	}

	latestAttempt := attempts[len(attempts)]
	lockoutExpiration := latestAttempt.Timestamp.Add(s.lockoutDuration)

	if time.Now().Before(lockoutExpiration) {
		return ErrUserLockedOut
	}

	return nil
}

func (s *LockoutService) SaveLoginAttempt(userID int, successful bool) error {
	return s.loginAttemptService.SaveAttempt(userID, &LoginAttempt{
		UserID:     userID,
		Successful: successful,
		Timestamp:  time.Now(),
	})
}
