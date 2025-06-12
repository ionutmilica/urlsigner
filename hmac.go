package urlsigner

import (
	"crypto/hmac"
	"hash"
)

type Encoding interface {
	EncodeToString(src []byte) string
	DecodeString(s string) ([]byte, error)
}

func SignWithEncoding(algorithm func() hash.Hash, encoding Encoding, key, payload string) string {
	mac := hmac.New(algorithm, []byte(key))
	mac.Write([]byte(payload))

	return encoding.EncodeToString(mac.Sum(nil))
}

// Sign will create a new signature based on a key and a string payload
// It is required to choose a hash algorithm
func Sign(algorithm func() hash.Hash, key, payload string) string {
	return SignWithEncoding(algorithm, Base64Encoding, key, payload)
}

func VerifyWithEncoding(encoding Encoding, b, a string) bool {
	mac1, err1 := encoding.DecodeString(a)
	mac2, err2 := encoding.DecodeString(b)
	if err1 != nil || err2 != nil {
		return false
	}

	return hmac.Equal(mac1, mac2)
}

// Verify will tell if two string signatures are equal
func Verify(a, b string) bool {
	return VerifyWithEncoding(Base64Encoding, b, a)
}
