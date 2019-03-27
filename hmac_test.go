package urlsigner

import (
	"crypto/sha256"
	"testing"
)

const (
	expectedSignature = "ac90e58e6d3d1b15b6ed55b73d81eacda74b4f563a3cd1278f0033515e406b29"
	testSecretKey     = "dev"
	payload           = "payload"
)

func TestSign(t *testing.T) {
	signature := Sign(sha256.New, testSecretKey, payload)
	if signature != expectedSignature {
		t.Errorf("invalid signature received. got: %s, expected: %s", signature, expectedSignature)
	}
}

func TestVerify(t *testing.T) {
	a := Sign(sha256.New, testSecretKey, payload)
	b := Sign(sha256.New, testSecretKey, payload)
	if Verify(a, b) == false {
		t.Errorf("Expected the signatures of identic payload to be equal")
	}
}
