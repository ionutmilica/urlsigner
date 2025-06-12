package urlsigner

import "errors"

var (
	ErrInvalidSignature = errors.New("invalid signature")
	ErrExpired          = errors.New("url has expired")
	ErrParseFailure     = errors.New("failed to parse URL")
)
