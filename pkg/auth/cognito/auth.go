// parkjunwoo.com/microstral/pkg/auth/cognito/auth.go
package cognito

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"parkjunwoo.com/microstral/pkg/auth"
)

type Auth struct {
	Region             string
	UserPoolID         string
	ClientID           string
	SigninCallbackURI  string
	SignoutCallbackURI string
	ResponseType       string
	JWKSUrl            string

	jwks *JWKS
	once sync.Once
}

func New(region, userPoolID, clientID, signinCallbackURI, signoutCallbackURI, responseType string) *Auth {
	return &Auth{
		Region:             region,
		UserPoolID:         userPoolID,
		ClientID:           clientID,
		SigninCallbackURI:  signinCallbackURI,
		SignoutCallbackURI: signoutCallbackURI,
		ResponseType:       responseType,
		JWKSUrl: fmt.Sprintf(
			"https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json",
			region,
			userPoolID,
		),
	}
}

func (ca *Auth) issuer() string {
	return fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", ca.Region, ca.UserPoolID)
}

func (ca *Auth) domain() string {
	return fmt.Sprintf("%s.auth.%s.amazoncognito.com", ca.UserPoolID, ca.Region)
}

// JWT 기반 인증
func (ca *Auth) Authenticate(c *gin.Context) (auth.Claims, bool, error) {
	tokenStr := extractBearerToken(c.Request)
	if tokenStr == "" {
		return auth.Claims{
			UserID: "guest",
			Email:  "",
			Roles:  []string{"Guest"},
		}, false, nil
	}

	token, err := jwt.Parse(tokenStr, ca.keyFunc)
	if err != nil || !token.Valid {
		return auth.Claims{}, false, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return auth.Claims{}, false, errors.New("invalid claims")
	}

	if claims["iss"] != ca.issuer() {
		return auth.Claims{}, false, errors.New("invalid issuer")
	}

	return auth.Claims{
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

func (ca *Auth) keyFunc(token *jwt.Token) (interface{}, error) {
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

	var roles []string
	for _, group := range groups {
		if role, ok := group.(string); ok {
			roles = append(roles, role)
		}
	}
	return roles
}
