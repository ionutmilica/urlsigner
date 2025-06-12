# 🔐 Go URL Signer

A lightweight Go library for generating and verifying **signed, expirable URLs** using HMAC (SHA-256 by default). Perfect for secure link sharing, protected downloads, and time-limited access.

---

## Features

- HMAC-based signing using any `crypto.Hash`
- Expirable URL support (`exp` query param)
- Easy to use with `string` or `url.URL`
- Constant-time signature verification
- Configurable field names and hash algorithm

## Installation

```bash
go get github.com/ionutmilica/urlsigner
```

## Usage
### Sign a URL (permanent)
```go
package main

import (
    "fmt"
    "github.com/ionutmilica/urlsigner"
)

func main() {
    signer := urlsigner.New("my-secret-key")

    signedURL, err := signer.SignURL("https://my-app.dev/resource?id=123")
    if err != nil {
        panic(err)
    }

    fmt.Println("Signed URL:", signedURL)
}
```

### Sign a URL with Expiration
```go
package main

import (
    "fmt"
    "time"
    "github.com/ionutmilica/urlsigner"
)

func main() {
    signer := urlsigner.New("my-secret-key")
    expiration := time.Now().Add(30 * time.Minute)

    signedURL, err := signer.SignURLWithExpiry("https://my-app.dev/protected", expiration)
    if err != nil {
        panic(err)
    }

    fmt.Println("Signed temporary URL:", signedURL)
}
```

### Verify a Signed URL
```go
err := signer.VerifyURL(signedURL)
if err != nil {
    fmt.Println("Invalid or expired URL:", err)
} else {
    fmt.Println("Valid URL ✅")
}
```

### Use with `url.URL` Objects Directly
```go
u, _ := url.Parse("https://my-app.dev/page")
signed := signer.Sign(*u)

err := signer.Verify(signed)
```

### Signing Arbitrary Payloads
#### Default settings
```go
signature := urlsigner.Sign(sha256.New, "key", "payload")
isValid := urlsigner.Verify(signature, "expected-signature")
```

#### Custom encoding
```go
signature := urlsigner.SignWithEncoding(sha256.New, HexEncoding, "key", "payload")
isValid := urlsigner.VerifyWithEncoding(HexEncoding, signature, "expected-signature")
```

### Custom Configuration
```go
signer := urlsigner.New("my-secret-key",
    urlsigner.WithSignatureField("signature"),
    urlsigner.WithExpirationField("expires"),
    urlsigner.WithAlgorithm(sha512.New),
    urlsigner.WithEncoding(HexEncoding)
)
```

## License
MIT License — see [LICENSE](./LICENSE) for details.
