// parkjunwoo.com/microstral/pkg/auth/auth.go

package auth

import "github.com/gin-gonic/gin"

type Authenticator interface {
	Authenticate(c *gin.Context) (Claims, bool, error)
}

type Claims struct {
	UserID string
	Roles  []string
	Email  string
	Extra  map[string]interface{}
}
