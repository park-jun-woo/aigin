// parkjunwoo.com/microstral/test/test.go
package test

import (
	mist "parkjunwoo.com/microstral"
	"parkjunwoo.com/microstral/pkg/auth/cognito"
)

func main() {
	// Mist 서버 생성
	s, err := mist.New("test.rego", true)
	if err != nil {
		panic(err)
	}

	auth := cognito.New(
		"ap-northeast-2", "userpoolid", "clientid",
		"https://yourdomain.com/signin-callback",
		"https://yourdomain.com/signout-callback",
		"code",
	)

	s.GET("/signin", auth.SigninHandler())
	s.GET("/signin-callback", auth.SigninCallbackHandler())
	s.GET("/signout", auth.SignoutHandler())
	s.GET("/signout-callback", auth.SignoutCallbackHandler())

	// 서버 실행
	s.Run()

}
