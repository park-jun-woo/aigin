// parkjunwoo.com/microstral/pkg/auth/auth.go

package auth

import "github.com/gin-gonic/gin"

type Authenticator interface {
	Authenticate(c *gin.Context) (Claims, bool, error)
}

type Claims struct {
	Usersub  string
	Username string
	Email    string
	Name     string
	Roles    []string
	Extra    map[string]interface{}
}

func GetClaims(c *gin.Context) Claims {
	claimsRaw, exists := c.Get("claims")
	if exists && claimsRaw != nil {
		if claims, ok := claimsRaw.(Claims); ok {
			return claims
		}
	}
	return Claims{Roles: []string{"Guest"}}
}
