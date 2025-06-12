package urlsigner

import (
	"crypto/hmac"
	"encoding/base64"
	"hash"
)

// Sign will create a new signature based on a key and a string payload
// It is required to choose a hash algorithm
func Sign(algorithm func() hash.Hash, key, payload string) string {
	mac := hmac.New(algorithm, []byte(key))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify will tell if two string signatures are equal
func Verify(a, b string) bool {
	mac1, err1 := base64.RawURLEncoding.DecodeString(a)
	mac2, err2 := base64.RawURLEncoding.DecodeString(b)
	if err1 != nil || err2 != nil {
		return false
	}

	return hmac.Equal(mac1, mac2)
}
