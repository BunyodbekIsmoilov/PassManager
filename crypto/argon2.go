package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/argon2"
)

// Argon2Params defines parameters for Argon2 hashing
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParams sets secure defaults for Argon2
var DefaultParams = Argon2Params{
	Memory:      64 * 1024, // 64 MB
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32, // 256-bit key
}

// HashPassword hashes a password using Argon2id
func HashPassword(password string, params Argon2Params) ([]byte, []byte, error) {
	if password == "" {
		return nil, nil, errors.New("password cannot be empty")
	}

	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}

	key := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	// Hash the derived key for storage
	storageKey := argon2.IDKey(
		key,
		salt,
		1,       // Single iteration
		64*1024, // 64MB memory
		1,       // Single thread
		params.KeyLength,
	)

	return storageKey, salt, nil
}

// VerifyPassword verifies a password against stored hash
func VerifyPassword(password string, salt, storedKey []byte, params Argon2Params) (bool, error) {
	if len(password) == 0 || len(salt) == 0 || len(storedKey) == 0 {
		return false, errors.New("invalid input parameters")
	}

	key := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	verifyKey := argon2.IDKey(
		key,
		salt,
		1, // Must match storage parameters
		64*1024,
		1,
		params.KeyLength,
	)

	return subtle.ConstantTimeCompare(verifyKey, storedKey) == 1, nil
}
