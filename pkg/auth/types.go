// internal/auth/types.go
package auth

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
)

type AuthProviderModel interface {
	// JWT 검증 미들웨어
	Authenticator() gin.HandlerFunc
	// 토큰 조회
	GetToken(ctx context.Context, code string) (*TokenResponse, error)
	// 토큰 갱신
	RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error)
	// 전체 사용자 목록 조회
	GetUsers(ctx context.Context) (*AllUsers, error)
	// 사용자 조회
	GetUser(ctx context.Context, id string) (*UsersItem, error)
	// 특정 사용자 그룹 목록 조회
	GetGroups(ctx context.Context, id string) ([]string, error)
	// 비밀번호 찾기(초기화 등) 요청
	PostForgot(ctx context.Context, id string) (bool, error)
	// 사용자 신규 생성 (id, name, email 등 입력)
	PostUser(ctx context.Context, id string, name string, email string) (string, error)
	// 사용자 정보 수정
	PutUser(ctx context.Context, id string, name string, email string) (bool, error)
}

type Claims struct {
	ID     string                 `json:"sub,omitempty"`
	Email  string                 `json:"email,omitempty"`
	Name   string                 `json:"name,omitempty"`
	Groups []string               `json:"groups,omitempty"`
	Extra  map[string]interface{} `json:"extra,omitempty"`
	jwt.RegisteredClaims
}

type UsersItem struct {
	ID            string         `json:"id"`
	Name          string         `json:"name,omitempty"`
	Email         string         `json:"email,omitempty"`
	EmailVerified string         `json:"email_verified,omitempty"`
	Status        string         `json:"status,omitempty"`
	CreatedAt     *time.Time     `json:"created_at,omitempty"`
	UpdatedAt     *time.Time     `json:"updated_at,omitempty"`
	DeletedAt     *time.Time     `json:"deleted_at,omitempty"`
	Groups        pq.StringArray `json:"groups"`
}

type UsersResult struct {
	Items   []UsersItem `json:"items"`
	Total   int         `json:"total"`
	Limit   int         `json:"limit"`
	Page    int         `json:"page"`
	Order   string      `json:"order"`
	Desc    string      `json:"desc"`
	HasNext bool        `json:"has_next"`
}

type AllUsers struct {
	Items []UsersItem `json:"items"`
}

type ForgotRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// PostUserRequest: 사용자 생성 요청 데이터
type PostUserRequest struct {
	ID    string `json:"id" binding:"required"`
	Name  string `json:"name" binding:"required"`
	Email string `json:"email" binding:"required,email"`
}

// PutUserRequest: 사용자 정보 업데이트 요청 데이터
type PutUserRequest struct {
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty"`
}

type TokenResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}
