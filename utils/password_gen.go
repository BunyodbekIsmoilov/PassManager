package utils

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"unicode"
)

const (
	Lowercase = "abcdefghijklmnopqrstuvwxyz"
	Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Digits    = "0123456789"
	Symbols   = "!@#$%^&*()_+-=[]{}|;:,.<>?"
)

type GeneratorConfig struct {
	Length     int
	UseLower   bool
	UseUpper   bool
	UseDigits  bool
	UseSymbols bool
}

func GeneratePassword(config GeneratorConfig) (string, error) {
	if config.Length < 8 {
		return "", errors.New("password length must be at least 8 characters")
	}

	charset := buildCharset(config)
	if charset == "" {
		return "", errors.New("no character sets selected")
	}

	password := make([]byte, config.Length)
	for i := 0; i < config.Length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		password[i] = charset[idx.Int64()]
	}

	// Ensure password meets complexity requirements
	if !meetsComplexity(string(password), config) {
		return GeneratePassword(config) // Retry if complexity not met
	}

	return string(password), nil
}

func buildCharset(config GeneratorConfig) string {
	var builder strings.Builder
	if config.UseLower {
		builder.WriteString(Lowercase)
	}
	if config.UseUpper {
		builder.WriteString(Uppercase)
	}
	if config.UseDigits {
		builder.WriteString(Digits)
	}
	if config.UseSymbols {
		builder.WriteString(Symbols)
	}
	return builder.String()
}

func meetsComplexity(password string, config GeneratorConfig) bool {
	hasLower := config.UseLower && strings.ContainsAny(password, Lowercase)
	hasUpper := config.UseUpper && strings.ContainsAny(password, Uppercase)
	hasDigit := config.UseDigits && strings.ContainsAny(password, Digits)
	hasSymbol := config.UseSymbols && strings.ContainsAny(password, Symbols)

	return (!config.UseLower || hasLower) &&
		(!config.UseUpper || hasUpper) &&
		(!config.UseDigits || hasDigit) &&
		(!config.UseSymbols || hasSymbol)
}

func EvaluatePasswordStrength(password string) int {
	if len(password) == 0 {
		return 0
	}

	score := 0
	// Length score (max 40 points)
	switch {
	case len(password) >= 16:
		score += 40
	case len(password) >= 12:
		score += 30
	case len(password) >= 8:
		score += 20
	default:
		score += 10
	}

	// Character diversity (max 60 points)
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, c := range password {
		switch {
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSymbol = true
		}
	}

	if hasLower {
		score += 10
	}
	if hasUpper {
		score += 10
	}
	if hasDigit {
		score += 10
	}
	if hasSymbol {
		score += 10
	}

	// Bonus for multiple character types
	types := 0
	if hasLower {
		types++
	}
	if hasUpper {
		types++
	}
	if hasDigit {
		types++
	}
	if hasSymbol {
		types++
	}

	switch types {
	case 2:
		score += 10
	case 3:
		score += 20
	case 4:
		score += 30
	}

	// Deduct for consecutive repeated characters
	for i := 0; i < len(password)-1; i++ {
		if password[i] == password[i+1] {
			score -= 5
		}
	}

	// Ensure score is within bounds
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}
