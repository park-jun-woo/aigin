// parkjunwoo.com/microstral/pkg/auth/cognito/handlers.go
package cognito

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"

	"github.com/gin-gonic/gin"
	"parkjunwoo.com/microstral/pkg/auth"
	"parkjunwoo.com/microstral/pkg/secure"
)

// OAuth2 로그인 시작 핸들러
func (ca *Auth) Signin() gin.HandlerFunc {
	return func(c *gin.Context) {
		query := url.Values{
			"response_type": {ca.ResponseType},
			"client_id":     {ca.ClientID},
			"redirect_uri":  {ca.SigninCallbackURI},
			"scope":         {"openid email profile"},
		}

		authURL := fmt.Sprintf("https://%s/oauth2/authorize?%s", ca.domain(), query.Encode())
		c.Redirect(http.StatusFound, authURL)
	}
}

// OAuth2 로그인 콜백 핸들러
func (ca *Auth) SigninCallback() gin.HandlerFunc {
	return func(c *gin.Context) {
		if ca.ResponseType == "code" {
			code := c.Query("code")
			if code == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "no authorization code provided"})
				return
			}
			// 코드로 토큰 교환 로직 구현 필요
			c.JSON(http.StatusOK, gin.H{"code": code})
			return
		}

		// implicit 방식(token)
		idToken := c.Query("id_token")
		if idToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no token provided"})
			return
		}

		// 토큰 검증 및 처리 로직
		c.JSON(http.StatusOK, gin.H{"id_token": idToken})
	}
}

// OAuth2 로그아웃 핸들러
func (ca *Auth) Signout() gin.HandlerFunc {
	return func(c *gin.Context) {
		logoutURL := fmt.Sprintf("https://%s/logout?%s", ca.domain(), url.Values{
			"client_id":  {ca.ClientID},
			"logout_uri": {ca.SignoutCallbackURI},
		}.Encode())

		c.Redirect(http.StatusFound, logoutURL)
	}
}

// OAuth2 로그아웃 콜백 핸들러 (필요시 추가로직 구현)
func (ca *Auth) SignoutCallback() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"msg": "Signed out successfully"})
	}
}

// ForgotPasswordRequest represents the input payload for forgot password.
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// 비밀번호 초기화 요청 핸들러
func (ca *Auth) PostForgot() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req ForgotPasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
			return
		}

		svc := cognitoidentityprovider.NewFromConfig(ca.awsCfg)

		secretHash := secure.CalcSecretHash(ca.ClientID, ca.ClientSecret, req.Email)

		input := &cognitoidentityprovider.ForgotPasswordInput{
			ClientId:   aws.String(ca.ClientID),
			Username:   aws.String(req.Email),
			SecretHash: aws.String(secretHash),
		}

		_, err := svc.ForgotPassword(c.Request.Context(), input)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "forgot password failed", "details": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Password reset initiated, check your email."})
	}
}

// 내정보 조회 핸들러
func (ca *Auth) GetMyinfo() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := auth.GetClaims(c)

		c.JSON(200, gin.H{
			"Usersub":  claims.Usersub,
			"Username": claims.Username,
			"Name":     claims.Name,
			"email":    claims.Email,
			"roles":    claims.Roles,
			"extra":    claims.Extra,
		})
	}
}

// GetUsers: 사용자 목록 조회 (Admin용)
func (ca *Auth) GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		limitInt, err := strconv.Atoi(c.DefaultQuery("limit", "48"))
		if err != nil || limitInt <= 0 {
			limitInt = 48
		}

		pageInt, err := strconv.Atoi(c.DefaultQuery("page", "1"))
		if err != nil || pageInt <= 0 {
			pageInt = 1
		}

		search := c.Query("search")

		var paginationToken *string
		currentPage := 1
		svc := ca.cognitoClient
		var users []types.UserType
		var nextPageToken *string

		for currentPage <= pageInt {
			input := &cognitoidentityprovider.ListUsersInput{
				UserPoolId:      aws.String(ca.UserPoolID),
				Limit:           aws.Int32(int32(limitInt)),
				PaginationToken: paginationToken,
			}

			if search != "" {
				input.Filter = aws.String(fmt.Sprintf(
					`username ^= "%[1]s" or email ^= "%[1]s" or name ^= "%[1]s"`,
					search))
			}

			resp, err := svc.ListUsers(c.Request.Context(), input)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":   "list users failed",
					"details": err.Error(),
				})
				return
			}

			if currentPage == pageInt {
				users = resp.Users
				nextPageToken = resp.PaginationToken
				break
			}

			if resp.PaginationToken == nil {
				users = []types.UserType{}
				nextPageToken = nil
				break
			}

			paginationToken = resp.PaginationToken
			currentPage++
		}

		response := gin.H{
			"page":  pageInt,
			"limit": limitInt,
			"items": users,
		}

		if nextPageToken != nil {
			response["hasNextPage"] = true
		} else {
			response["hasNextPage"] = false
		}

		c.JSON(http.StatusOK, response)
	}
}

// GetUser: 특정 사용자 조회 (Admin용)
func (ca *Auth) GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.Param("username")
		if username == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username required"})
			return
		}

		svc := ca.cognitoClient

		input := &cognitoidentityprovider.AdminGetUserInput{
			UserPoolId: aws.String(ca.UserPoolID),
			Username:   aws.String(username),
		}

		resp, err := svc.AdminGetUser(c.Request.Context(), input)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "get user failed", "details": err.Error()})
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

// PostUserRequest: 사용자 생성 요청 데이터
type PostUserRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Name     string `json:"name"`
}

// PostUser: 새 사용자 생성 (Admin용)
func (ca *Auth) PostUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req PostUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
			return
		}

		svc := ca.cognitoClient

		input := &cognitoidentityprovider.AdminCreateUserInput{
			UserPoolId: aws.String(ca.UserPoolID),
			Username:   aws.String(req.Username),
			UserAttributes: []types.AttributeType{
				{Name: aws.String("email"), Value: aws.String(req.Email)},
				{Name: aws.String("name"), Value: aws.String(req.Name)},
				{Name: aws.String("email_verified"), Value: aws.String("true")},
			},
			MessageAction: "SUPPRESS", // 초대 이메일 발송 억제
		}

		resp, err := svc.AdminCreateUser(c.Request.Context(), input)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "create user failed", "details": err.Error()})
			return
		}

		c.JSON(http.StatusOK, resp.User)
	}
}

// PutUserRequest: 사용자 정보 업데이트 요청 데이터
type PutUserRequest struct {
	Email *string `json:"email,omitempty"`
	Name  *string `json:"name,omitempty"`
}

// PutUser: 사용자 정보 수정 (Admin용)
func (ca *Auth) PutUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.Param("username")
		if username == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username required"})
			return
		}

		var req PutUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
			return
		}

		svc := ca.cognitoClient

		var attributes []types.AttributeType

		if req.Email != nil {
			attributes = append(attributes, types.AttributeType{
				Name:  aws.String("email"),
				Value: req.Email,
			})
		}

		if req.Name != nil {
			attributes = append(attributes, types.AttributeType{
				Name:  aws.String("name"),
				Value: req.Name,
			})
		}

		if len(attributes) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no attributes provided"})
			return
		}

		input := &cognitoidentityprovider.AdminUpdateUserAttributesInput{
			UserPoolId:     aws.String(ca.UserPoolID),
			Username:       aws.String(username),
			UserAttributes: attributes,
		}

		_, err := svc.AdminUpdateUserAttributes(c.Request.Context(), input)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "update user failed", "details": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "user updated successfully"})
	}
}
