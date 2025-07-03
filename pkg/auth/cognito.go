// parkjunwoo.com/microstral/pkg/auth/cognito.go

package auth

import (
	"errors"
	"net/http"
	"strings"
	"sync"

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
			UserID: "",
			Email:  "",
			Roles:  []string{"Guest"}, // JWT 없으면 Guest 역할 부여
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

// KeyFunc 로직은 Cognito의 JWKS 처리 구현 필요
func (ca *CognitoAuthenticator) keyFunc(token *jwt.Token) (interface{}, error) {
	ca.once.Do(func() {
		ca.jwks = fetchJWKS(ca.JWKSUrl)
	})
	return ca.jwks.KeyFunc(token)
}

func parseRoles(claims jwt.MapClaims) []string {
	rolesInterface, ok := claims["cognito:groups"].([]interface{})
	if !ok {
		return []string{}
	}

	var roles []string
	for _, r := range rolesInterface {
		roles = append(roles, r.(string))
	}
	return roles
}

// JWKS는 Cognito에서 공개키 가져오는 구조체
type JWKS struct {
	// JWKS 로직 추가
}

func fetchJWKS(url string) *JWKS {
	// JWKS Fetch 로직 구현 필요
	return &JWKS{}
}

func (j *JWKS) KeyFunc(token *jwt.Token) (interface{}, error) {
	// JWKS 기반 keyFunc 구현 필요
	return nil, nil
}
