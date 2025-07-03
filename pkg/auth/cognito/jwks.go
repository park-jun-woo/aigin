// parkjunwoo.com/microstral/pkg/auth/cognito/jwks.go
package cognito

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// 이하 기존 JWKS 로직 유지
type JWKS struct {
	Keys map[string]JWK
	mu   sync.RWMutex
}

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func fetchJWKS(url string) *JWKS {
	jwks := &JWKS{Keys: make(map[string]JWK)}
	jwks.refresh(url)

	go func() {
		for {
			time.Sleep(time.Hour)
			jwks.refresh(url)
		}
	}()

	return jwks
}

func (j *JWKS) refresh(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("JWKS fetch error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var data struct {
		Keys []JWK `json:"keys"`
	}

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		fmt.Printf("JWKS decode error: %v\n", err)
		return
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	j.Keys = make(map[string]JWK)
	for _, key := range data.Keys {
		j.Keys[key.Kid] = key
	}
}

func (j *JWKS) getPublicKey(kid string) (*rsa.PublicKey, error) {
	j.mu.RLock()
	key, exists := j.Keys[kid]
	j.mu.RUnlock()

	if !exists {
		return nil, errors.New("public key not found")
	}

	return keyToRSAPublicKey(key.N, key.E)
}

func keyToRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, _ := base64.RawURLEncoding.DecodeString(nStr)
	eBytes, _ := base64.RawURLEncoding.DecodeString(eStr)

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}
