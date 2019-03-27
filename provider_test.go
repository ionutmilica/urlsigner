package urlsigner

import (
	"crypto/sha256"
	"net/url"
	"reflect"
	"testing"
	"time"
)

const (
	providerPrivateKey = "dev"
)

func TestSignerProvider_Sign(t *testing.T) {
	signer := SignerProvider{
		secretKey: providerPrivateKey,
		expField:  "exp",
		sigField:  "sig",
		algorithm: sha256.New,
	}

	type test struct {
		input  url.URL
		output url.URL
	}

	tests := []test{
		{
			input: url.URL{
				Scheme: "https",
				Host:   "app.dev",
			},
			output: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "sig=94e47b2343a0bd746779894cc7ede3cd97bc60ad3dfccb993573ee88ada49e83",
			},
		},
		{
			input: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&b=3",
			},
			output: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&b=3&sig=cd6b95263b267a926faa4faa69c5112a045a1d6cd3c9c167ac6b588d9f41181a",
			},
		},
		// Query params are sorted
		{
			input: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&z=3",
			},
			output: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&sig=471b1a21d03f1a744946c6ffbcabdfb7ab4ef03dc6813d90a52182cd3d278bb1&z=3",
			},
		},
		// Only query params
		{
			input: url.URL{
				RawQuery: "a=2&b=3",
			},
			output: url.URL{
				RawQuery: "a=2&b=3&sig=8e50c474bab96ea73f51d2e144a67ebde29a34265fd61e9852a29ccbc6c37b6a",
			},
		},
	}

	for _, test := range tests {
		if got := signer.Sign(test.input); !reflect.DeepEqual(got, test.output) {
			t.Errorf("sign failed, expected %s but got %s", test.output.String(), got.String())
		}
		// Also check the alias
		if got := signer.SignURL(test.input.String()); !reflect.DeepEqual(got, test.output.String()) {
			t.Errorf("sign failed, expected %s but got %s", test.output.String(), got)
		}
	}
}

func TestSignerProvider_SignTemporary(t *testing.T) {
	now := time.Date(2019, 03, 27, 12, 00, 00, 0, time.UTC)

	signer := SignerProvider{
		secretKey: providerPrivateKey,
		expField:  "exp",
		sigField:  "sig",
		algorithm: sha256.New,
		nowFn: func() time.Time {
			return now
		},
	}

	type test struct {
		input  url.URL
		output url.URL
		exp    time.Time
	}

	tests := []test{
		{
			input: url.URL{
				Scheme: "https",
				Host:   "app.dev",
			},
			output: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "exp=1553691600&sig=14f49cdb033981431924e83f7b22233ad2639161474ad064337b96e326bf6d11",
			},
			exp: now.Add(time.Hour),
		},
		{
			input: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&b=3",
			},
			output: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&b=3&exp=1553695200&sig=5bc7b061306f2a6f2679e8d2f0290e576542a3d303fb0a5696c277c0ea0d623b",
			},
			exp: now.Add(time.Hour * 2),
		},
		// Query params are sorted
		{
			input: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&z=3",
			},
			output: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&exp=1553691600&sig=002844ecb1d1bbccc30fd9727717ef8715e80a5b147874018a79aa5ea5e64036&z=3",
			},
			exp: now.Add(time.Hour),
		},
	}

	for _, test := range tests {
		if got := signer.SignTemporary(test.input, test.exp); !reflect.DeepEqual(got, test.output) {
			t.Errorf("sign failed, expected %s but got %s", test.output.String(), got.String())
		}
		// Also check the alias
		if got := signer.SignTemporaryURL(test.input.String(), test.exp); !reflect.DeepEqual(got, test.output.String()) {
			t.Errorf("sign failed, expected %s but got %s", test.output.String(), got)
		}
	}
}

func TestSignerProvider_Verify(t *testing.T) {
	signer := SignerProvider{
		secretKey: providerPrivateKey,
		expField:  "exp",
		sigField:  "sig",
		algorithm: sha256.New,
	}

	type test struct {
		input  url.URL
		output bool
	}

	tests := []test{
		{
			input: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "sig=94e47b2343a0bd746779894cc7ede3cd97bc60ad3dfccb993573ee88ada49e83",
			},
			output: true,
		},
		{
			input: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&b=3&sig=cd6b95263b267a926faa4faa69c5112a045a1d6cd3c9c167ac6b588d9f41181a",
			},
			output: true,
		},
		// Query params are sorted
		{
			input: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&sig=471b1a21d03f1a744946c6ffbcabdfb7ab4ef03dc6813d90a52182cd3d278bb1&z=3",
			},
			output: true,
		},
		{
			input: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&sig=471b1a21d03f1a224946c6ffbcabdfb7ab4ef03dc6813d90a52182cd3d278bb1&z=3",
			},
			output: false,
		},
		{
			input: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&sig=&z=3",
			},
			output: false,
		},
	}

	for _, test := range tests {
		if got := signer.Verify(test.input); !reflect.DeepEqual(got, test.output) {
			t.Errorf("sign failed, expected %v but got %v", test.output, got)
		}
		// Also check the alias
		if got := signer.VerifyURL(test.input.String()); !reflect.DeepEqual(got, test.output) {
			t.Errorf("sign failed, expected %v but got %v", test.output, got)
		}
	}
}

func TestSignerProvider_VerifyTemporary(t *testing.T) {
	now := time.Date(2019, 03, 27, 12, 00, 00, 0, time.UTC)

	signer := SignerProvider{
		secretKey: providerPrivateKey,
		expField:  "exp",
		sigField:  "sig",
		algorithm: sha256.New,
		nowFn: func() time.Time {
			return now
		},
	}

	type test struct {
		input  url.URL
		output bool
	}

	tests := []test{
		{
			input: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "exp=1553691600&sig=14f49cdb033981431924e83f7b22233ad2639161474ad064337b96e326bf6d11",
			},
			output: true,
		},
		{
			input: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&b=3&exp=1553695200&sig=5bc7b061306f2a6f2679e8d2f0290e576542a3d303fb0a5696c277c0ea0d623b",
			},
			output: true,
		},
		// Query params are sorted
		{
			input: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&exp=1553691600&sig=002844ecb1d1bbccc30fd9727717ef8715e80a5b147874018a79aa5ea5e64036&z=3",
			},
			output: true,
		},
		{
			input: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&sig=471b1a21d03f1a224946c6ffbcabdfb7ab4ef03dc6813d90a52182cd3d278bb1&z=3",
			},
			output: false,
		},
		{
			input: url.URL{
				Scheme:   "https",
				Host:     "app.dev",
				RawQuery: "a=2&sig=&z=3",
			},
			output: false,
		},
	}

	for _, test := range tests {
		if got := signer.VerifyTemporary(test.input); !reflect.DeepEqual(got, test.output) {
			t.Errorf("verify temporary failed for %s: expected %v but got %v", test.input.String(), test.output, got)
		}
		// Also check the alias
		if got := signer.VerifyTemporaryURL(test.input.String()); !reflect.DeepEqual(got, test.output) {
			t.Errorf("verify temporary url failed for %s expected %v but got %v", test.input.String(), test.output, got)
		}
	}
}
