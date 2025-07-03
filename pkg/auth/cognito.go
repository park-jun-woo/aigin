package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type CognitoAuthenticator struct {
	Region     string
	UserPoolID string
	JWKSUrl    string

	jwks *JWKS
	once sync.Once
}

func (ca *CognitoAuthenticator) Authenticate(c *gin.Context) (Claims, bool, error) {
	tokenStr := extractBearerToken(c.Request)
	if tokenStr == "" {
		return Claims{
			UserID: "guest",
			Email:  "",
			Roles:  []string{"Guest"},
		}, false, nil
	}

	token, err := jwt.Parse(tokenStr, ca.keyFunc)
	if err != nil || !token.Valid {
		return Claims{}, false, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return Claims{}, false, errors.New("invalid claims")
	}

	return Claims{
		UserID: claims["sub"].(string),
		Email:  claims["email"].(string),
		Roles:  parseRoles(claims),
	}, true, nil
}

func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	parts := strings.Split(authHeader, " ")
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}
	return ""
}

func (ca *CognitoAuthenticator) keyFunc(token *jwt.Token) (interface{}, error) {
	ca.once.Do(func() {
		ca.jwks = fetchJWKS(ca.JWKSUrl)
	})

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("no kid found in token header")
	}

	return ca.jwks.getPublicKey(kid)
}

func parseRoles(claims jwt.MapClaims) []string {
	groups, ok := claims["cognito:groups"].([]interface{})
	if !ok {
		return []string{}
	}

	roles := []string{}
	for _, group := range groups {
		if role, ok := group.(string); ok {
			roles = append(roles, role)
		}
	}

	return roles
}

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
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, err
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)

	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}
