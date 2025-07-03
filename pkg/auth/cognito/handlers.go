// parkjunwoo.com/microstral/pkg/auth/cognito/handlers.go
package cognito

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

// OAuth2 로그인 시작 핸들러
func (ca *Auth) SigninHandler() gin.HandlerFunc {
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
func (ca *Auth) SigninCallbackHandler() gin.HandlerFunc {
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
func (ca *Auth) SignoutHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		logoutURL := fmt.Sprintf("https://%s/logout?%s", ca.domain(), url.Values{
			"client_id":  {ca.ClientID},
			"logout_uri": {ca.SignoutCallbackURI},
		}.Encode())

		c.Redirect(http.StatusFound, logoutURL)
	}
}

// OAuth2 로그아웃 콜백 핸들러 (필요시 추가로직 구현)
func (ca *Auth) SignoutCallbackHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"msg": "Signed out successfully"})
	}
}
