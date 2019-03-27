## Go URL Signer

### Installation:

```bash
go get github.com/ionutmilica/urlsigner
```

### Examples:

#### Signing an url string
```go
package main

import "github.com/ionutmilica/urlsigner"

func main()  {
    signer := urlsigner.New("key")
    signedUrl := signer.SignURL("https://my-app.dev?page=protected")

    // Verifying is as simple as providing the signed url:
    println(signer.VerifyURL(signedUrl))
}
```
Equivalent methods *Sign* and *Verify* are provided for when you want to use url.URL structs instead of strings.

#### Signing an url for a limited period
```go
package main

import (
	"github.com/ionutmilica/urlsigner"
	"time"
)

func main()  {
    signer := urlsigner.New("key")
    expiration := time.Now().UTC().Add(time.Hour)
    signedUrl := signer.SignTemporaryURL("https://my-app.dev?page=protected", expiration)

    // Verifying is as simple as providing the signed url:
    println(signer.VerifyTemporaryURL(signedUrl))
}
```

Equivalent methods *SignTemporary* and *VerifyTemporary* are provided for when you want to use url.URL structs instead of strings.


#### Signing primitives
```go
signature := urlsigner.Sign(sha256.New, "key", "payload")
isValid := urlsigner.Verify(signature, "expected-signature")
```

#### Todo:
- Route signing
- HTTP middleware for route signing
