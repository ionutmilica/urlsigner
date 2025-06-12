package urlsigner

import (
	"crypto/sha256"
	"hash"
	"net/url"
	"strconv"
	"time"
)

// SignerProvider is used to sign and verify urls.
type SignerProvider struct {
	secretKey string
	sigField  string
	expField  string
	encoding  Encoding
	nowFn     func() time.Time
	algorithm func() hash.Hash
}

// Sign will sign a URL object returning it updated to include the signature
func (p *SignerProvider) Sign(u url.URL) url.URL {
	signature := SignWithEncoding(p.algorithm, p.encoding, p.secretKey, u.String())

	q := u.Query()
	q.Set(p.sigField, signature)
	u.RawQuery = q.Encode()

	return u
}

// SignWithExpiry will sign a URL object for a limited period of time returning
// it updated with two new query strings: signature, expiration
func (p *SignerProvider) SignWithExpiry(u url.URL, expireAt time.Time) url.URL {
	q := u.Query()
	q.Set(p.expField, strconv.FormatInt(expireAt.Unix(), 10))
	u.RawQuery = q.Encode()

	return p.Sign(u)
}

// SignWithTTL will sign a URL object for a limited period of time returning
// it updated with two new query strings: signature, expiration
func (p *SignerProvider) SignWithTTL(u url.URL, ttl time.Duration) url.URL {
	return p.SignWithExpiry(u, p.nowFn().Add(ttl))
}

// SignURL acts like Sign method but accepts the url as string instead of url.URL
func (p *SignerProvider) SignURL(rawURL string) (string, error) {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return "", ErrParseFailure
	}

	newURL := p.Sign(*u)

	return newURL.String(), nil
}

// SignURLWithExpiry acts like SignWithExpiry method but accepts the url as string instead of url.URL
func (p *SignerProvider) SignURLWithExpiry(rawURL string, expireAt time.Time) (string, error) {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return "", ErrParseFailure
	}

	newURL := p.SignWithExpiry(*u, expireAt)

	return newURL.String(), nil
}

func (p *SignerProvider) SignURLWithTTL(rawURL string, ttl time.Duration) (string, error) {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return "", ErrParseFailure
	}
	newUrl := p.SignWithTTL(*u, ttl)
	return newUrl.String(), nil
}

// Verify will check a URL object against its signature
// This signature should be provided by the url itself in a query string
func (p *SignerProvider) Verify(u url.URL) error {
	q := u.Query()
	signature := q.Get(p.sigField)
	if signature == "" {
		return ErrInvalidSignature
	}

	if expStr := q.Get(p.expField); expStr != "" {
		expUnix, err := strconv.ParseInt(expStr, 10, 64)
		if err != nil {
			return ErrExpired
		}
		if time.Unix(expUnix, 0).Before(p.nowFn()) {
			return ErrExpired
		}
	}

	q.Del(p.sigField)

	u.RawQuery = q.Encode()
	u.Fragment = ""

	computedSignature := Sign(p.algorithm, p.secretKey, u.String())

	if !VerifyWithEncoding(p.encoding, computedSignature, signature) {
		return ErrInvalidSignature
	}

	return nil
}

// VerifyURL acts like Verify method but accepts the url as string instead of url.URL
func (p *SignerProvider) VerifyURL(rawURL string) error {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return ErrParseFailure
	}

	return p.Verify(*u)
}

// New will create a new SignerProvider.
//
//	urlsigner.New("secret-key")
func New(secretKey string, opts ...func(*SignerProvider)) *SignerProvider {
	provider := &SignerProvider{
		secretKey: secretKey,
		expField:  "exp",
		sigField:  "sig",
		algorithm: sha256.New,
		encoding:  Base64Encoding,
		nowFn: func() time.Time {
			return time.Now().UTC()
		},
	}

	for _, opt := range opts {
		opt(provider)
	}

	return provider
}

// WithAlgorithm allows overriding of the internal hashing algorithm
func WithAlgorithm(alg func() hash.Hash) func(*SignerProvider) {
	return func(provider *SignerProvider) { provider.algorithm = alg }
}

// WithExpirationField allows overriding of the internal field name for expiration
func WithExpirationField(name string) func(*SignerProvider) {
	return func(provider *SignerProvider) {
		provider.expField = name
	}
}

// WithSignatureField allows overriding of the internal field name for signature
func WithSignatureField(name string) func(*SignerProvider) {
	return func(provider *SignerProvider) {
		provider.sigField = name
	}
}

// WithEncoding allows overriding of the internal encoding mechanism
func WithEncoding(encoding Encoding) func(*SignerProvider) {
	return func(provider *SignerProvider) {
		provider.encoding = encoding
	}
}
