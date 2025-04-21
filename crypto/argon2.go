package crypto

import (
	"errors"

	"golang.org/x/crypto/argon2"
)

// Argon2Params defines parameters for Argon2 key derivation.
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParams sets secure defaults for Argon2.
var DefaultParams = Argon2Params{
	Memory:      64 * 1024, // 64 MB
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32, // 256-bit key
}

// DeriveKey derives a key from a password using Argon2id.
func DeriveKey(password string, salt []byte) ([]byte, error) {
	if password == "" {
		return nil, errors.New("password cannot be empty")
	}
	return argon2.IDKey([]byte(password), salt,
		DefaultParams.Iterations, DefaultParams.Memory,
		DefaultParams.Parallelism, DefaultParams.KeyLength), nil
}

// GetEncryptedCheck encrypts a known value for master key verification.
func GetEncryptedCheck(key []byte) ([]byte, error) {
	return Encrypt([]byte("SPMS"), key)
}

// VerifyMasterKey verifies if the key can decrypt the check value.
func VerifyMasterKey(key, encryptedCheck []byte) bool {
	plaintext, err := Decrypt(encryptedCheck, key)
	return err == nil && string(plaintext) == "SPMS"
}
