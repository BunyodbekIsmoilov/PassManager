package crypto

// ClearBytes securely wipes sensitive data from memory.
func ClearBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}
