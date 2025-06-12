package urlsigner

import (
	"crypto/md5"
	"crypto/sha256"
	"errors"
	"hash"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	providerPrivateKey = "dev"
)

var hostOnlyUrl, queryOnlyUrl, hostAndQueryUrl, hostAndQuerySortedUrl url.URL

func init() {
	hostOnlyUrl = url.URL{
		Scheme: "https",
		Host:   "app.dev",
	}
	queryOnlyUrl = url.URL{
		RawQuery: "a=2&b=3",
	}
	hostAndQueryUrl = url.URL{
		Scheme:   "https",
		Host:     "app.dev",
		RawQuery: "a=2&b=3",
	}
	hostAndQuerySortedUrl = url.URL{
		Scheme:   "https",
		Host:     "app.dev",
		RawQuery: "a=2&z=3",
	}
}

func TestSignerProvider_Sign_Verify_OnlyHost(t *testing.T) {
	signer := New(providerPrivateKey)

	signed := signer.Sign(hostOnlyUrl)
	expectedQuery := "sig=lOR7I0OgvXRneYlMx-3jzZe8YK09_MuZNXPuiK2knoM"

	if signed.RawQuery != expectedQuery {
		t.Fatalf("signed query did not match: %v", signed.RawQuery)
	}

	if err := signer.Verify(signed); err != nil {
		t.Fatalf("signature should verify, got error: %v", err)
	}
}

func TestSignerProvider_Sign_Verify_HostAndQuery(t *testing.T) {
	signer := New(providerPrivateKey)

	signed := signer.Sign(hostAndQueryUrl)
	expectedQuery := "a=2&b=3&sig=zWuVJjsmepJvqk-qacURKgRaHWzTycFnrGtYjZ9BGBo"

	if signed.RawQuery != expectedQuery {
		t.Fatalf("signed query did not match: %v", signed.RawQuery)
	}

	if err := signer.Verify(signed); err != nil {
		t.Fatalf("signature should verify, got error: %v", err)
	}
}

func TestSignerProvider_Sign_Verify_HostAndQuerySorted(t *testing.T) {
	signer := New(providerPrivateKey)

	signed := signer.Sign(hostAndQuerySortedUrl)
	expectedQuery := "a=2&sig=RxsaIdA_GnRJRsb_vKvft6tO8D3GgT2QpSGCzT0ni7E&z=3"

	if signed.RawQuery != expectedQuery {
		t.Fatalf("signed query did not match: %v", signed.RawQuery)
	}

	if err := signer.Verify(signed); err != nil {
		t.Fatalf("signature should verify, got error: %v", err)
	}
}

func TestSignerProvider_Sign_Verify_OnlyQuery(t *testing.T) {
	signer := New(providerPrivateKey)

	signed := signer.Sign(queryOnlyUrl)
	expectedQuery := "a=2&b=3&sig=jlDEdLq5bqc_UdLhRKZ-veKaNCZf1h6YUqKcy8bDe2o"

	if signed.RawQuery != expectedQuery {
		t.Fatalf("signed query did not match: %v", signed.RawQuery)
	}

	if err := signer.Verify(signed); err != nil {
		t.Fatalf("signature should verify, got error: %v", err)
	}
}

func TestSignerProvider_SignWithExpiry_Verify_OnlyHost(t *testing.T) {
	now := time.Date(2019, 03, 27, 12, 00, 00, 0, time.UTC)
	signer := &SignerProvider{
		secretKey: providerPrivateKey,
		expField:  "exp",
		sigField:  "sig",
		algorithm: sha256.New,
		nowFn: func() time.Time {
			return now
		},
	}

	signed := signer.SignWithExpiry(hostOnlyUrl, now.Add(time.Hour))
	expectedQuery := "exp=1553691600&sig=FPSc2wM5gUMZJOg_eyIjOtJjkWFHStBkM3uW4ya_bRE"

	if signed.RawQuery != expectedQuery {
		t.Fatalf("signed query did not match: %v", signed.RawQuery)
	}

	if err := signer.Verify(signed); err != nil {
		t.Fatalf("signature should verify, got error: %v", err)
	}
}

func TestSignerProvider_SignWithExpiry_Verify_HostAndQuery(t *testing.T) {
	now := time.Date(2019, 03, 27, 12, 00, 00, 0, time.UTC)
	signer := &SignerProvider{
		secretKey: providerPrivateKey,
		expField:  "exp",
		sigField:  "sig",
		algorithm: sha256.New,
		nowFn: func() time.Time {
			return now
		},
	}

	signed := signer.SignWithExpiry(hostAndQueryUrl, now.Add(time.Hour))
	expectedQuery := "a=2&b=3&exp=1553691600&sig=PWPE8Y033xCXF-1GwQSDUe2eIyrhb6gQ53EzqW970Y8"

	if signed.RawQuery != expectedQuery {
		t.Fatalf("signed query did not match: %v", signed.RawQuery)
	}

	if err := signer.Verify(signed); err != nil {
		t.Fatalf("signature should verify, got error: %v", err)
	}
}

func TestSignerProvider_Verify_MissingSignature(t *testing.T) {
	signer := New(providerPrivateKey)

	u := url.URL{
		Scheme: "https",
		Host:   "blah.com",
		Path:   "/api/v1",
	}
	err := signer.Verify(u)

	if err == nil {
		t.Fatal("verification should not pass when sig is not present")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("got unexpected error: %v", err)
	}
}

func TestSignerProvider_Verify_InvalidSignature(t *testing.T) {
	signer := New(providerPrivateKey)

	u := url.URL{
		Scheme:   "https",
		Host:     "blah.com",
		Path:     "/api/v1",
		RawQuery: "sig=blah",
	}
	err := signer.Verify(u)

	if err == nil {
		t.Fatal("verification should not pass when sig is not valid")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("got unexpected error: %v", err)
	}
}

func TestSignerProvider_Verify_InvalidExpiration(t *testing.T) {
	signer := New(providerPrivateKey)

	u := url.URL{
		Scheme:   "https",
		Host:     "blah.com",
		Path:     "/api/v1",
		RawQuery: "sig=blah&exp=string",
	}
	err := signer.Verify(u)

	if err == nil {
		t.Fatal("verification should not pass when expiration field is not valid")
	}
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("got unexpected error: %v", err)
	}
}

func TestSignerProvider_Verify_Expired(t *testing.T) {
	now := time.Date(2019, 03, 27, 12, 00, 00, 0, time.UTC)
	signer := &SignerProvider{
		secretKey: providerPrivateKey,
		expField:  "exp",
		sigField:  "sig",
		algorithm: sha256.New,
		nowFn: func() time.Time {
			return now
		},
	}

	signedUrl := signer.SignWithExpiry(url.URL{
		Scheme: "https",
		Host:   "",
	}, now.Add(time.Hour*-1))

	err := signer.Verify(signedUrl)

	if err == nil {
		t.Fatal("verification should not pass when signatures is expired")
	}
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("invalid signature error: %v", err)
	}
}

func TestSignerProvider_SignURL_Verify_HostAndQuery(t *testing.T) {
	signer := New(providerPrivateKey)

	expectedQuery := "https://app.dev?a=2&b=3&sig=zWuVJjsmepJvqk-qacURKgRaHWzTycFnrGtYjZ9BGBo"

	signed, err := signer.SignURL(hostAndQueryUrl.String())
	if err != nil {
		t.Fatalf("signer should sign URL, got error: %v", err)
	}

	if signed != expectedQuery {
		t.Fatalf("signed query did not match: %v", signed)
	}

	if err := signer.VerifyURL(signed); err != nil {
		t.Fatalf("signature should verify, got error: %v", err)
	}
}

func TestSignerProvider_SignURL_Verify_Malformed(t *testing.T) {
	signer := New(providerPrivateKey)

	_, err := signer.SignURL("")
	if err == nil {
		t.Fatalf("signer should return error when url is : %v", err)
	}
}

func TestSignerProvider_VerifyURL_Malformed(t *testing.T) {
	signer := New(providerPrivateKey)

	err := signer.VerifyURL("")
	if err == nil {
		t.Fatalf("signer should return error when url is : %v", err)
	}
}

func TestSignerProvider_SignURLWithExpiry_Verify_HostAndQuery(t *testing.T) {
	now := time.Date(2019, 03, 27, 12, 00, 00, 0, time.UTC)
	signer := &SignerProvider{
		secretKey: providerPrivateKey,
		expField:  "exp",
		sigField:  "sig",
		algorithm: sha256.New,
		nowFn: func() time.Time {
			return now
		},
	}

	expectedQuery := "https://app.dev?a=2&b=3&exp=1553695200&sig=W8ewYTBvKm8meejS8CkOV2VCo9MD-wpWlsJ3wOoNYjs"

	signed, err := signer.SignURLWithExpiry(hostAndQueryUrl.String(), now.Add(time.Hour*2))
	if err != nil {
		t.Fatalf("signer should sign URL, got error: %v", err)
	}

	if signed != expectedQuery {
		t.Fatalf("signed query did not match: %v", signed)
	}

	if err := signer.VerifyURL(signed); err != nil {
		t.Fatalf("signature should verify, got error: %v", err)
	}
}

func TestSignerProvider_SignURLWithExpiry_Verify_Malformed(t *testing.T) {
	now := time.Date(2019, 03, 27, 12, 00, 00, 0, time.UTC)
	signer := &SignerProvider{
		secretKey: providerPrivateKey,
		expField:  "exp",
		sigField:  "sig",
		algorithm: sha256.New,
		nowFn: func() time.Time {
			return now
		},
	}

	_, err := signer.SignURLWithExpiry("", now.Add(time.Hour*2))
	if err == nil {
		t.Fatalf("signer should return error when url is : %v", err)
	}
}

func TestSignerProvider_SignWithTTL_Verify_HostAndQuery(t *testing.T) {
	now := time.Date(2019, 03, 27, 12, 00, 00, 0, time.UTC)
	signer := &SignerProvider{
		secretKey: providerPrivateKey,
		expField:  "exp",
		sigField:  "sig",
		algorithm: sha256.New,
		nowFn: func() time.Time {
			return now
		},
	}

	expectedQuery := "https://app.dev?a=2&b=3&exp=1553691600&sig=PWPE8Y033xCXF-1GwQSDUe2eIyrhb6gQ53EzqW970Y8"

	signed, err := signer.SignURLWithTTL(hostAndQueryUrl.String(), time.Hour)
	if err != nil {
		t.Fatalf("signer should sign URL, got error: %v", err)
	}

	if signed != expectedQuery {
		t.Fatalf("signed query did not match: %v", signed)
	}

	if err := signer.VerifyURL(signed); err != nil {
		t.Fatalf("signature should verify, got error: %v", err)
	}
}

func TestSignerProvider_SignURLWithTTL_Verify_Malformed(t *testing.T) {
	now := time.Date(2019, 03, 27, 12, 00, 00, 0, time.UTC)
	signer := &SignerProvider{
		secretKey: providerPrivateKey,
		expField:  "exp",
		sigField:  "sig",
		algorithm: sha256.New,
		nowFn: func() time.Time {
			return now
		},
	}

	_, err := signer.SignURLWithTTL("", time.Hour)
	if err == nil {
		t.Fatalf("signer should return error when url is : %v", err)
	}
}

// Options
func TestSignerProvider_Options_CustomSignatureField(t *testing.T) {
	signer := New(providerPrivateKey, SignatureField("siga"))

	signedUrl, err := signer.SignURL("https://my-app.dev")
	if err != nil {
		t.Fatalf("signer returned an error: %v", err)
	}

	if !strings.Contains(signedUrl, "siga=") {
		t.Fatalf("signer should contain custom signature field but got: %v", signedUrl)
	}
}

func TestSignerProvider_Options_CustomExpirationField(t *testing.T) {
	signer := New(providerPrivateKey, ExpirationField("expa"))

	signedUrl, err := signer.SignURLWithTTL("https://my-app.dev", time.Hour)
	if err != nil {
		t.Fatalf("signer returned an error: %v", err)
	}

	if !strings.Contains(signedUrl, "expa=") {
		t.Fatalf("signer should contain custom signature field but got: %v", signedUrl)
	}
}

func TestSignerProvider_Options_CustomAlgorithm(t *testing.T) {
	signer := New(providerPrivateKey, Algorithm(func() hash.Hash {
		return md5.New()
	}))

	_, err := signer.SignURLWithTTL("https://my-app.dev", time.Hour)
	if err != nil {
		t.Fatalf("signer returned an error: %v", err)
	}
}
