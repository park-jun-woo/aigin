// internal/auth/CognitoModel.go
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"

	"parkjunwoo.com/microstral/pkg/env"
	"parkjunwoo.com/microstral/pkg/secure"
)

type CognitoModel struct {
	Client             *cognitoidentityprovider.Client
	Host               string
	UserPoolID         string
	ClientID           string
	ClientSecret       string
	Issuer             string
	SigninCallbackURI  string
	SignoutCallbackURI string
	JWKS               keyfunc.Keyfunc

	TokenExpiresIn   int
	IDExpiresIn      int
	RefreshExpiresIn int
}

func NewCognitoModel(awsCfg aws.Config) *CognitoModel {
	// 환경 변수에서 설정 값 가져오기
	clientSecretName := env.GetEnv("AUTH_CLIENT_SECRET", "")
	jwksURL := env.GetEnv("AUTH_JWKS_URL", "")
	// AWS Secrets Manager 클라이언트 생성
	smClient := secretsmanager.NewFromConfig(awsCfg)
	// 클라이언트 시크릿을 가져오기
	clientSecret, err := smClient.GetSecretValue(context.TODO(), &secretsmanager.GetSecretValueInput{
		SecretId: &clientSecretName,
	})
	if err != nil {
		log.Fatalf("unable to retrieve secret %s: %w", clientSecretName, err)
		return nil
	}
	// JWKS 인스턴스 생성
	keyfunc, err := keyfunc.NewDefault([]string{jwksURL})
	if err != nil {
		log.Fatalf("failed to create JWKS keyfunc: %v", err)
		return nil
	}
	// CognitoModel 인스턴스 생성
	return &CognitoModel{
		Client:             cognitoidentityprovider.NewFromConfig(awsCfg),
		Host:               env.GetEnv("AUTH_HOST", ""),
		UserPoolID:         env.GetEnv("AUTH_USERPOOL_ID", ""),
		ClientID:           env.GetEnv("AUTH_CLIENT_ID", ""),
		ClientSecret:       *clientSecret.SecretString,
		Issuer:             env.GetEnv("AUTH_ISSUER", ""),
		SigninCallbackURI:  env.GetEnv("AUTH_SIGNIN_CALLBACK", ""),
		SignoutCallbackURI: env.GetEnv("AUTH_SIGNOUT_CALLBACK", ""),
		JWKS:               keyfunc,

		TokenExpiresIn:   env.GetEnvInt("AUTH_TOKEN_EXPIRES_IN", 3600),          // 기본 1시간
		IDExpiresIn:      env.GetEnvInt("AUTH_ID_EXPIRES_IN", 3600),             // 기본 1시간
		RefreshExpiresIn: env.GetEnvInt("AUTH_REFRESH_EXPIRES_IN", 60*60*24*30), // 기본 30일
	}
}

// Authenticator 미들웨어, 요청의 JWT 토큰을 검증하고 claims를 설정합니다.
func (m *CognitoModel) Authenticator() gin.HandlerFunc {
	return func(c *gin.Context) {
		guestClaims := Claims{Groups: []string{"Guest"}}
		var claims *Claims
		// 1. t쿠키 검증
		tokenStr, err := c.Cookie("t")
		if err == nil && tokenStr != "" {
			token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, m.JWKS.Keyfunc)
			if err == nil && token.Valid {
				if c2, ok := token.Claims.(*Claims); ok {
					claims = c2
				}
			}
		}
		// 2. t쿠키가 없거나 만료/검증실패일 때 r쿠키로 재발급 시도
		if claims == nil {
			refreshToken, err := c.Cookie("r")
			if err == nil && refreshToken != "" {
				newTokenRes, err := m.RefreshToken(c.Request.Context(), refreshToken)
				if err == nil {
					// 새 토큰 쿠키 재설정
					c.SetCookie("t", newTokenRes.IDToken, m.IDExpiresIn, "/", m.Host, true, true)
					c.SetCookie("r", newTokenRes.RefreshToken, m.RefreshExpiresIn, "/", m.Host, true, true)
					// 다시 검증해서 claims 설정
					token, err := jwt.ParseWithClaims(newTokenRes.IDToken, &Claims{}, m.JWKS.Keyfunc)
					if err == nil && token.Valid {
						if c2, ok := token.Claims.(*Claims); ok {
							claims = c2
						}
					}
				}
			}
		}
		// 3. 유효한 claims가 없으면 guest 처리
		if claims == nil {
			c.Set("claims", guestClaims)
			c.Next()
			return
		}
		// ----[ Issuer 검증 ]----
		if m.Issuer != "" && claims.Issuer != m.Issuer {
			c.Set("claims", guestClaims)
			c.Next()
			return
		}
		// ----[ Audience 검증 ]----
		audMatch := false
		if len(claims.Audience) > 0 {
			for _, aud := range claims.Audience {
				if aud == m.ClientID {
					audMatch = true
					break
				}
			}
		}
		if m.ClientID != "" && !audMatch {
			c.Set("claims", guestClaims)
			c.Next()
			return
		}
		// ----[ Groups 필드 추출 보정 ]----
		groups := claims.Groups
		if groups == nil && claims.Extra != nil {
			if g, ok := claims.Extra["cognito:groups"].([]interface{}); ok {
				groups = make([]string, 0, len(g))
				for _, v := range g {
					if s, ok := v.(string); ok {
						groups = append(groups, s)
					}
				}
				claims.Groups = groups
			}
		}
		c.Set("claims", claims)
		c.Next()
	}
}

func (m *CognitoModel) GetToken(ctx context.Context, code string) (*TokenResponse, error) {
	tokenEndpoint := fmt.Sprintf("%s/oauth2/token", m.Host)

	reqBody := fmt.Sprintf(
		"grant_type=authorization_code&client_id=%s&code=%s&redirect_uri=%s",
		m.ClientID, code, m.SigninCallbackURI,
	)

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if m.ClientSecret != "" {
		authHeader := "Basic " + secure.BasicAuth(m.ClientID, m.ClientSecret)
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get token: %s", resp.Status)
	}

	var tokenRes TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenRes); err != nil {
		return nil, err
	}

	// ID Token 검증 (선택적으로 Claims 파싱 가능)
	_, err = jwt.Parse(tokenRes.IDToken, m.JWKS.Keyfunc)
	if err != nil {
		return nil, err
	}

	return &tokenRes, nil
}

// TokenResponse 구조체는 GetToken과 동일하게 사용
func (m *CognitoModel) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	tokenEndpoint := fmt.Sprintf("%s/oauth2/token", m.Host)

	reqBody := fmt.Sprintf(
		"grant_type=refresh_token&client_id=%s&refresh_token=%s",
		m.ClientID, refreshToken,
	)
	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if m.ClientSecret != "" {
		authHeader := "Basic " + secure.BasicAuth(m.ClientID, m.ClientSecret)
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to refresh token: %s", resp.Status)
	}

	var tokenRes TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenRes); err != nil {
		return nil, err
	}

	// ID Token 검증
	_, err = jwt.Parse(tokenRes.IDToken, m.JWKS.Keyfunc)
	if err != nil {
		return nil, err
	}

	return &tokenRes, nil
}

func (m *CognitoModel) GetUsers(ctx context.Context) (*AllUsers, error) {
	var users []UsersItem

	input := &cognitoidentityprovider.ListUsersInput{
		UserPoolId: &m.UserPoolID,
		Limit:      aws.Int32(60), // Cognito API 제한: 최대 60
	}

	// Cognito는 페이징 기반 (PaginationToken 사용)
	for {
		output, err := m.Client.ListUsers(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list users from Cognito: %w", err)
		}

		for _, u := range output.Users {
			item := UsersItem{
				ID:     *u.Username,
				Groups: pq.StringArray{},
			}

			for _, attr := range u.Attributes {
				switch *attr.Name {
				case "name":
					item.Name = aws.ToString(attr.Value)
				case "email":
					item.Email = aws.ToString(attr.Value)
				case "email_verified":
					item.EmailVerified = aws.ToString(attr.Value)
				}
			}

			if u.UserStatus != "" {
				item.Status = string(u.UserStatus)
			}
			if u.UserCreateDate != nil {
				t := *u.UserCreateDate
				item.CreatedAt = &t
			}
			if u.UserLastModifiedDate != nil {
				t := *u.UserLastModifiedDate
				item.UpdatedAt = &t
			}

			// 그룹 정보 추가 (Optional, 퍼포먼스에 민감하면 생략)
			groups, err := m.GetGroups(ctx, item.ID)
			if err == nil && len(groups) > 0 {
				item.Groups = pq.StringArray(groups)
			}

			users = append(users, item)
		}

		// 다음 페이지 있으면 계속, 아니면 종료
		if output.PaginationToken == nil || *output.PaginationToken == "" {
			break
		}
		input.PaginationToken = output.PaginationToken
	}

	return &AllUsers{Items: users}, nil
}

func (m *CognitoModel) GetUser(ctx context.Context, id string) (*UsersItem, error) {
	input := &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: aws.String(m.UserPoolID),
		Username:   aws.String(id),
	}

	resp, err := m.Client.AdminGetUser(ctx, input)
	if err != nil {
		return nil, err
	}

	var user UsersItem
	user.ID = id
	user.Status = string(resp.UserStatus)
	user.CreatedAt = resp.UserCreateDate
	user.UpdatedAt = resp.UserLastModifiedDate
	for _, attr := range resp.UserAttributes {
		switch *attr.Name {
		case "name":
			user.Name = aws.ToString(attr.Value)
		case "email":
			user.Email = aws.ToString(attr.Value)
		case "email_verified":
			user.EmailVerified = aws.ToString(attr.Value)
		}
	}

	return &user, nil
}

// 사용자 그룹 가져오기 (보통은 별도 최적화 필요, 대용량이면 병렬화 또는 배치 필수)
func (m *CognitoModel) GetGroups(ctx context.Context, id string) ([]string, error) {
	input := &cognitoidentityprovider.AdminListGroupsForUserInput{
		Username:   &id,
		UserPoolId: &m.UserPoolID,
	}
	output, err := m.Client.AdminListGroupsForUser(ctx, input)
	if err != nil {
		return nil, err
	}
	var groups []string
	for _, g := range output.Groups {
		if g.GroupName != nil {
			groups = append(groups, *g.GroupName)
		}
	}
	return groups, nil
}

func (m *CognitoModel) PostForgot(ctx context.Context, id string) (bool, error) {
	secretHash := secure.CalcSecretHash(m.ClientID, m.ClientSecret, id)
	input := &cognitoidentityprovider.ForgotPasswordInput{
		ClientId:   aws.String(m.ClientID),
		Username:   aws.String(id),
		SecretHash: aws.String(secretHash),
	}

	_, err := m.Client.ForgotPassword(ctx, input)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (m *CognitoModel) PostUser(ctx context.Context, id string, name string, email string) (string, error) {
	input := &cognitoidentityprovider.AdminCreateUserInput{
		UserPoolId: aws.String(m.UserPoolID),
		Username:   aws.String(id),
		UserAttributes: []types.AttributeType{
			{Name: aws.String("name"), Value: aws.String(name)},
			{Name: aws.String("email"), Value: aws.String(email)},
		},
		MessageAction: "SUPPRESS", // 초대 이메일 발송 억제
	}

	resp, err := m.Client.AdminCreateUser(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}

	return *resp.User.Username, nil
}

func (m *CognitoModel) PutUser(ctx context.Context, id string, name string, email string) (bool, error) {
	input := &cognitoidentityprovider.AdminUpdateUserAttributesInput{
		UserPoolId: aws.String(m.UserPoolID),
		Username:   aws.String(id),
		UserAttributes: []types.AttributeType{
			{Name: aws.String("name"), Value: aws.String(name)},
			{Name: aws.String("email"), Value: aws.String(email)},
		},
	}

	_, err := m.Client.AdminUpdateUserAttributes(ctx, input)
	if err != nil {
		return false, fmt.Errorf("failed to update user attributes: %w", err)
	}

	return true, nil
}
