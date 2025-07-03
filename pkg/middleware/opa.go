// parkjunwoo.com/microstral/pkg/middleware/opa.go
package middleware

import (
	"context"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/gin-gonic/gin"
	"github.com/open-policy-agent/opa/v1/rego"
	"parkjunwoo.com/microstral/pkg/auth"
	"parkjunwoo.com/microstral/pkg/file"
)

var (
	policySrc atomic.Value // thread-safe 정책 문자열
	onceInit  atomic.Bool  // 최초 한번만 WatchFile 실행
)

// 정책 파일 핫리로드 및 초기화
func initPolicyHotReload(path string) {
	if onceInit.Swap(true) { // 이미 초기화 됐으면 skip
		return
	}

	err := file.WatchFile(path, func(data []byte) {
		policySrc.Store(string(data))
		log.Printf("OPA policy reloaded: %s", path)
	})
	if err != nil {
		log.Fatalf("Failed to watch policy file: %v", err)
	}
}

func OPA(path string) gin.HandlerFunc {
	// 미들웨어가 최초 실행될 때 핫리로드 초기화
	initPolicyHotReload(path)

	return func(c *gin.Context) {
		policy, ok := policySrc.Load().(string)
		if !ok || policy == "" {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "OPA policy load error"})
			return
		}

		claims := auth.GetClaims(c)

		input := map[string]interface{}{
			"path":   c.Request.URL.Path,
			"method": c.Request.Method,
			"userID": claims.UserID,
			"roles":  claims.Roles,
		}

		ctx := context.Background()
		query, err := rego.New(
			rego.Query("data.httpapi.allow"),
			rego.Module("policy.rego", policy),
			rego.Input(input),
		).PrepareForEval(ctx)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "OPA policy error"})
			return
		}

		rs, err := query.Eval(ctx)
		if err != nil || len(rs) == 0 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "OPA eval error"})
			return
		}

		allowed, ok := rs[0].Expressions[0].Value.(bool)
		if !ok || !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "OPA denied"})
			return
		}

		// 통과
		c.Next()
	}
}
