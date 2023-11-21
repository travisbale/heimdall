package argon2

import (
	"errors"

	"github.com/travisbale/heimdall/internal/heimdall"
)

type PasswordHasher struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func NewPasswordHasher(memory, iterations, saltLength, keyLength uint32, parallelism uint8) *PasswordHasher {
	return &PasswordHasher{
		memory: memory,
		iterations: iterations,
		parallelism: parallelism,
		saltLength: saltLength,
		keyLength: keyLength,
	}
}

func (h *PasswordHasher) Hash(password string) (string, error) {
	return hashPassword(h.memory, h.iterations, h.saltLength, h.keyLength, h.parallelism, password)
}

func (*PasswordHasher) Verify(encodedHash string, password string) error {
	if err := compareHashAndPassword(encodedHash, password); err != nil {
		if errors.Is(err, errMismatchedHashAndPassword) {
			return heimdall.ErrIncorrectPassword
		}

		return err
	}

	return nil
}
