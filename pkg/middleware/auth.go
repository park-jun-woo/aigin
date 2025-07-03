// https://parkjunwoo.com/microstral/pkg/middleware/auth.go
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 쿠키에서 JWT 추출
		tokenString, err := c.Cookie("t")
		if err != nil {
			c.Next()
			return
		}

		// JWT 파싱
		// 실제 구현 시, 아래 `[]byte("secret")` 자리에는
		// 서명 검증에 사용할 시크릿 키(혹은 공개키)를 넣어주세요.
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte("secret"), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "유효하지 않은 JWT 토큰입니다.",
			})
			return
		}

		// Claims를 gin.Context에 저장하여 다른 미들웨어/핸들러에서 사용 가능하도록 함
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("JWTClaims", claims)
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "유효하지 않은 JWT 토큰입니다.",
			})
			return
		}

		c.Next()
	}
}
