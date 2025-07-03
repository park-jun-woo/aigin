// https://parkjunwoo.com/microstral/pkg/middleware/origin.go
package middleware

import (
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"parkjunwoo.com/microstral/pkg/env"
)

func Origin() gin.HandlerFunc {
	allowedEnv := env.GetEnv("ALLOWED_ORIGIN", "")
	if allowedEnv == "" {
		// ALLOWED_ORIGIN이 설정되어 있지 않으면 미들웨어를 빈 함수로 반환
		return func(c *gin.Context) {
			c.Next()
		}
	}

	hasWildcard := strings.Contains(allowedEnv, "*")
	var re *regexp.Regexp
	if hasWildcard {
		pattern := regexp.QuoteMeta(allowedEnv)
		pattern = strings.ReplaceAll(pattern, "\\*", ".*")
		pattern = "^" + pattern + "$"
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			log.Printf("failed to compile ALLOWED_ORIGIN pattern: %v", err)
			// 오류가 발생하면 미들웨어를 빈 함수로 반환
			return func(c *gin.Context) {
				c.Next()
			}
		}
	}

	return func(c *gin.Context) {
		requestOrigin := c.Request.Header.Get("Origin")
		if requestOrigin == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Origin not allowed"})
			return
		}
		allowed := false
		if hasWildcard && re != nil {
			if re.MatchString(requestOrigin) {
				allowed = true
			}
		} else {
			if allowedEnv == requestOrigin {
				allowed = true
			}
		}
		if allowed {
			c.Writer.Header().Set("Access-Control-Allow-Origin", requestOrigin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Origin not allowed"})
			return
		}
	}
}
