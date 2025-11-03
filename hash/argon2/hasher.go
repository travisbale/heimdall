package argon2

type Argon2Hasher struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func NewArgon2Hasher(memory, iterations, saltLength, keyLength uint32, parallelism uint8) *Argon2Hasher {
	return &Argon2Hasher{
		memory:      memory,
		iterations:  iterations,
		parallelism: parallelism,
		saltLength:  saltLength,
		keyLength:   keyLength,
	}
}

func (h *Argon2Hasher) HashPassword(password string) (string, error) {
	return hashPassword(h.memory, h.iterations, h.saltLength, h.keyLength, h.parallelism, password)
}

func (*Argon2Hasher) VerifyPassword(password string, encodedHash string) error {
	return compareHashAndPassword(password, encodedHash)
}
