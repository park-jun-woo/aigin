// parkjunwoo.com/microstral/pkg/middleware/auth.go
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"parkjunwoo.com/microstral/pkg/auth"
)

func Auth(authenticator auth.Authenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, _, err := authenticator.Authenticate(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		// JWT가 없더라도 Guest Claims 저장됨
		c.Set("claims", claims)

		c.Next()
	}
}
