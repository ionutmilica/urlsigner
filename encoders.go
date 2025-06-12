package urlsigner

import (
	"encoding/base64"
	"encoding/hex"
)

type hexEncoding struct {
}

func (e *hexEncoding) DecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func (e *hexEncoding) EncodeToString(src []byte) string {
	return hex.EncodeToString(src)
}

type base64Encoding struct {
}

func (e *base64Encoding) DecodeString(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func (e *base64Encoding) EncodeToString(src []byte) string {
	return base64.RawURLEncoding.EncodeToString(src)
}

var HexEncoding = &hexEncoding{}
var Base64Encoding = &base64Encoding{}
