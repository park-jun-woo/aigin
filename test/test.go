// parkjunwoo.com/microstral/test/test.go
package test

import (
	mist "parkjunwoo.com/microstral"
	"parkjunwoo.com/microstral/pkg/auth/cognito"
	"parkjunwoo.com/microstral/pkg/middleware"
)

func main() {
	// Mist 서버 생성
	s, err := mist.New(true)
	if err != nil {
		panic(err)
	}

	authenticator := cognito.New(
		"ap-northeast-2", "userpoolid", "clientid",
		"https://yourdomain.com/signin-callback",
		"https://yourdomain.com/signout-callback",
		"code",
	)

	s.Use(middleware.Origin())
	s.Use(middleware.Auth(authenticator))
	s.Use(middleware.OPA("test.rego"))

	// OAuth 핸들러 추가
	s.GET("/signin", authenticator.SigninHandler())
	s.GET("/signin-callback", authenticator.SigninCallbackHandler())
	s.GET("/signout", authenticator.SignoutHandler())
	s.GET("/signout-callback", authenticator.SignoutCallbackHandler())

	// 서버 실행
	s.Run()
}
