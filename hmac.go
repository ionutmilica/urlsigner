package urlsigner

import (
	"crypto/hmac"
	"encoding/hex"
	"hash"
)

// Sign will create a new signature based on a key and a string payload
// It is required to choose a hash algorithm
func Sign(algorithm func() hash.Hash, key, payload string) string {
	mac := hmac.New(algorithm, []byte(key))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify will tell if two string signatures are equal
func Verify(a, b string) bool {
	mac1, err := hex.DecodeString(a)
	if err != nil {
		return false
	}

	mac2, err := hex.DecodeString(b)
	if err != nil {
		return false
	}

	return hmac.Equal(mac1, mac2)
}
