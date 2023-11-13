package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var errInvalidHash = errors.New("the encoded hash is not in the correct format")
var errIncompatibleVersion = errors.New("incompatible version of argon2")
var errMismatchedHashAndPassword = errors.New("encodedHash is not the hash of the given password")

func hashPassword(memory, iterations, saltLength, keyLength uint32, parallelism uint8, password string) (string, error) {
	salt, err := generateSalt(saltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, iterations, parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

func compareHashAndPassword(encodedHash, password string) error {
	memory, iterations, parallelism, keyLength, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return err
	}

	otherHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)

	if subtle.ConstantTimeCompare(hash, otherHash) != 1 {
		return errMismatchedHashAndPassword
	}

	return nil
}

func generateSalt(saltLength uint32) ([]byte, error) {
	bytes := make([]byte, saltLength)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func decodeHash(encodedHash string) (uint32, uint32, uint8, uint32, []byte, []byte, error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return 0, 0, 0, 0, nil, nil, errInvalidHash
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return 0, 0, 0, 0, nil, nil, err
	}
	if version != argon2.Version {
		return 0, 0, 0, 0, nil, nil, errIncompatibleVersion
	}

	var memory uint32
	var iterations uint32
	var parallelism uint8
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return 0, 0, 0, 0, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return 0, 0, 0, 0, nil, nil, err
	}

	hash, err := base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return 0, 0, 0, 0, nil, nil, err
	}

	return memory, iterations, parallelism, uint32(len(hash)), salt, hash, nil
}
