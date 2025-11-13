package argon2

type Config struct {
	Memory      uint32
	Iterations  uint32
	SaltLength  uint32
	KeyLength   uint32
	Parallelism uint8
}

// Hasher provides Argon2id password hashing with configurable parameters
// Default config uses OWASP recommendations (64MB memory, 2 iterations, 4 threads)
type Hasher struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func NewHasher(config *Config) *Hasher {
	return &Hasher{
		memory:      config.Memory,
		iterations:  config.Iterations,
		parallelism: config.Parallelism,
		saltLength:  config.SaltLength,
		keyLength:   config.KeyLength,
	}
}

func (h *Hasher) HashPassword(password string) (string, error) {
	return hashPassword(h.memory, h.iterations, h.saltLength, h.keyLength, h.parallelism, password)
}

func (*Hasher) VerifyPassword(password string, encodedHash string) error {
	return compareHashAndPassword(password, encodedHash)
}
