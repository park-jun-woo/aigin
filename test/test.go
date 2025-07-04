// parkjunwoo.com/microstral/test/test.go
package test

import (
	mist "parkjunwoo.com/microstral"
	"parkjunwoo.com/microstral/pkg/auth/cognito"
	"parkjunwoo.com/microstral/pkg/middleware"
)

func main() {
	// Mist 서버 생성
	s, err := mist.New(false, true)
	if err != nil {
		panic(err)
	}

	authenticator, err := cognito.New(s.GetHost(), "code")
	if err != nil {
		panic(err)
	}

	s.Use(middleware.Origin())
	s.Use(middleware.Auth(authenticator))
	s.Use(middleware.OPA())

	// OAuth 핸들러 추가
	s.GET("/signin", authenticator.Signin())
	s.GET("/signin-callback", authenticator.SigninCallback())
	s.GET("/signout", authenticator.Signout())
	s.GET("/signout-callback", authenticator.SignoutCallback())
	s.POST("/forgot", authenticator.PostForgot())
	s.GET("/myinfo", authenticator.GetMyinfo())
	s.GET("/users", authenticator.GetUsers())
	s.GET("/users/:username", authenticator.GetUser())
	s.POST("/users", authenticator.PostUser())
	s.PUT("/users/:username", authenticator.PutUser())

	// 서버 실행
	s.Run()
}
