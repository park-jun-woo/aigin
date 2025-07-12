// parkjunwoo.com/microstral/test/test.go
package test

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	mist "parkjunwoo.com/microstral"
	"parkjunwoo.com/microstral/pkg/auth"
	"parkjunwoo.com/microstral/pkg/cloudfront"
	"parkjunwoo.com/microstral/pkg/env"
	"parkjunwoo.com/microstral/pkg/middleware"
)

func main() {
	// Mist 서버 생성
	s, err := mist.New(false, true)
	if err != nil {
		panic(err)
	}
	// AWS 설정 로드
	region := env.GetEnv("AWS_REGION", "")
	awsCfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		panic(err)
	}
	// Postgres 데이터베이스 연결
	db, err := s.Postgres()
	if err != nil {
		panic(err)
	}
	// 모델 인스턴스 생성
	groupModel := auth.NewGroupModel(db)
	userModel := auth.NewUserModel(db)
	cognitoModel := auth.NewCognitoModel(awsCfg)
	cloudFrontModel := cloudfront.NewCloudFrontModel(awsCfg)
	// 컨트롤러 인스턴스 생성
	userCtrl := auth.NewUserController(groupModel, userModel, cognitoModel, cloudFrontModel)

	s.Use(middleware.Origin())
	s.Use(cognitoModel.Authenticator())
	s.Use(middleware.OPA())

	// OAuth 핸들러 추가
	s.GET("/signin", userCtrl.Signin)
	s.GET("/signin-callback", userCtrl.SigninCallback)
	s.GET("/signout", userCtrl.Signout)
	s.GET("/signout-callback", userCtrl.SignoutCallback)
	s.POST("/forgot", userCtrl.PostForgot)
	s.GET("/myinfo", userCtrl.GetMyinfo)
	s.GET("/users", userCtrl.GetUsers)
	s.GET("/users/:id", userCtrl.GetUser)
	s.POST("/users", userCtrl.PostUser)
	s.PUT("/users/:id", userCtrl.PutUser)

	// 서버 실행
	s.Run()
}
