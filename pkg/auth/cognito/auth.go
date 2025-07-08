// parkjunwoo.com/microstral/pkg/auth/cognito/auth.go
package cognito

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"parkjunwoo.com/microstral/pkg/auth"
	"parkjunwoo.com/microstral/pkg/env"
	"parkjunwoo.com/microstral/pkg/secure"
)

type Auth struct {
	Domain             string
	Region             string
	UserPoolID         string
	ClientID           string
	ClientSecret       string
	SigninURI          string
	SigninCallbackURI  string
	SignoutURI         string
	SignoutCallbackURI string
	CloudfrontID       string
	SignedCookieSecret string
	ResponseType       string
	JWKSUrl            string

	jwks          *JWKS
	awsCfg        aws.Config
	cognitoClient *cognitoidentityprovider.Client
	once          sync.Once
}

func GetSecretValue(cfg aws.Config, secretName string) (string, error) {
	svc := secretsmanager.NewFromConfig(cfg)
	result, err := svc.GetSecretValue(context.TODO(), &secretsmanager.GetSecretValueInput{
		SecretId: &secretName,
	})
	if err != nil {
		return "", fmt.Errorf("unable to retrieve secret %s: %w", secretName, err)
	}
	return *result.SecretString, nil
}

func New(responseType string) (*Auth, error) {
	domain := env.GetEnv("ALLOWED_ORIGINS", "")
	region := env.GetEnv("COGNITO_REGION", "")
	userPoolID := env.GetEnv("COGNITO_USERPOOL_ID", "")
	clientID := env.GetEnv("COGNITO_CLIENT_ID", "")
	clientSecretName := env.GetEnv("COGNITO_CLIENT_SECRET", "")
	signinURI := env.GetEnv("COGNITO_SIGNIN", "")
	signinCallbackURI := env.GetEnv("COGNITO_SIGNIN_CALLBACK", "")
	signoutURI := env.GetEnv("COGNITO_SIGNOUT", "")
	signoutCallbackURI := env.GetEnv("COGNITO_SIGNOUT_CALLBACK", "")
	cloudfrontID := env.GetEnv("CLOUDFRONT_ID", "")
	signedCookieSecretName := env.GetEnv("SIGNED_COOKIE_SECRET", "")

	awsCfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, err
	}

	clientSecret, err := GetSecretValue(awsCfg, clientSecretName)
	if err != nil {
		log.Printf("failed to get secret: %v", err)
		return nil, err
	}

	signedCookieSecret, err := GetSecretValue(awsCfg, signedCookieSecretName)
	if err != nil {
		log.Printf("failed to get secret: %v", err)
		return nil, err
	}

	cognitoClient := cognitoidentityprovider.NewFromConfig(awsCfg)

	return &Auth{
		Domain:             domain,
		Region:             region,
		UserPoolID:         userPoolID,
		ClientID:           clientID,
		ClientSecret:       clientSecret,
		SigninURI:          signinURI,
		SigninCallbackURI:  signinCallbackURI,
		SignoutURI:         signoutURI,
		SignoutCallbackURI: signoutCallbackURI,
		CloudfrontID:       cloudfrontID,
		SignedCookieSecret: signedCookieSecret,
		ResponseType:       responseType,
		JWKSUrl: fmt.Sprintf(
			"https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json",
			region,
			userPoolID,
		),
		awsCfg:        awsCfg,
		cognitoClient: cognitoClient,
	}, nil
}

func (ca *Auth) issuer() string {
	return fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", ca.Region, ca.UserPoolID)
}

func (ca *Auth) domain() string {
	return fmt.Sprintf("%s.auth.%s.amazoncognito.com", ca.UserPoolID, ca.Region)
}

func (ca *Auth) refreshIDToken(refreshToken string) (string, error) {
	input := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: "REFRESH_TOKEN_AUTH",
		ClientId: aws.String(ca.ClientID),
		AuthParameters: map[string]string{
			"REFRESH_TOKEN": refreshToken,
		},
	}

	if ca.ClientSecret != "" {
		secretHash := secure.BasicAuth(ca.ClientID, ca.ClientSecret)
		input.AuthParameters["SECRET_HASH"] = secretHash
	}

	resp, err := ca.cognitoClient.InitiateAuth(context.TODO(), input)
	if err != nil {
		return "", fmt.Errorf("failed to refresh token: %w", err)
	}

	if resp.AuthenticationResult == nil || resp.AuthenticationResult.IdToken == nil {
		return "", errors.New("no id_token in refresh response")
	}

	return *resp.AuthenticationResult.IdToken, nil
}

// JWT 기반 인증
func (ca *Auth) Authenticate(c *gin.Context) (auth.Claims, bool, error) {
	var tokenStr string

	// 1. Authorization 헤더 우선
	tokenStr = extractBearerToken(c.Request)

	// 2. 없으면 쿠키 t에서 가져오기
	if tokenStr == "" {
		cookie, err := c.Cookie("t")
		if err == nil {
			tokenStr = cookie
		}
	}

	if tokenStr == "" {
		// JWT 없으면 Guest 권한 반환
		return auth.Claims{
			Roles: []string{"Guest"},
		}, false, nil
	}

	// 3. 파싱 시도
	claims, valid, err := ca.parseJWT(tokenStr)
	if err == nil && valid {
		return claims, true, nil
	}

	// 4. access token이 만료됐거나 없음 → 쿠키 r 시도
	refreshToken, err := c.Cookie("r")
	if err != nil || refreshToken == "" {
		// 리프레시 토큰도 없으면 Guest
		return auth.Claims{Roles: []string{"Guest"}}, false, nil
	}

	// 5. Cognito에 refresh token으로 새 토큰 요청
	newIDToken, err := ca.refreshIDToken(refreshToken)
	if err != nil {
		return auth.Claims{Roles: []string{"Guest"}}, false, nil
	}

	// 6. 쿠키 갱신
	c.SetCookie("t", newIDToken, 3600, "/", ca.Domain, true, true)

	// 7. 새 토큰으로 인증 재시도
	claims, valid, err = ca.parseJWT(newIDToken)
	if err != nil || !valid {
		return auth.Claims{Roles: []string{"Guest"}}, false, nil
	}

	return claims, true, nil
}

func (ca *Auth) parseJWT(tokenStr string) (auth.Claims, bool, error) {
	if tokenStr == "" {
		return auth.Claims{}, false, errors.New("empty token")
	}

	token, err := jwt.Parse(tokenStr, ca.keyFunc)
	if err != nil || !token.Valid {
		return auth.Claims{}, false, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return auth.Claims{}, false, errors.New("invalid claims format")
	}

	// issuer 검증
	if iss, ok := claims["iss"].(string); !ok || iss != ca.issuer() {
		return auth.Claims{}, false, errors.New("invalid issuer")
	}

	return auth.Claims{
		Usersub:  claims["sub"].(string),
		Username: claims["cognito:username"].(string),
		Name:     claims["name"].(string),
		Email:    claims["email"].(string),
		Roles:    parseRoles(claims),
	}, true, nil
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

func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	parts := strings.Split(authHeader, " ")
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}
	return ""
}
