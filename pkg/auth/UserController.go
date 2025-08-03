// pkg/auth/UserController.go
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"parkjunwoo.com/aigin/pkg/cloudfront"
	"parkjunwoo.com/aigin/pkg/env"
	"parkjunwoo.com/aigin/pkg/param"
)

type UserController struct {
	GroupModel *GroupModel
	UserModel  *UserModel
	AuthModel  AuthProviderModel
	CDNModel   *cloudfront.CloudFrontModel

	Servername string
	SigninURI  string
	SignoutURI string

	TokenExpiresIn   int
	IDExpiresIn      int
	RefreshExpiresIn int
}

func NewUserController(
	groupModel *GroupModel, userModel *UserModel, authModel AuthProviderModel, cdnModel *cloudfront.CloudFrontModel,
) *UserController {
	return &UserController{
		UserModel:  userModel,
		GroupModel: groupModel,
		AuthModel:  authModel,
		CDNModel:   cdnModel,

		Servername: env.GetEnv("SERVERNAME", ""),
		SigninURI:  env.GetEnv("AUTH_SIGNIN", ""),
		SignoutURI: env.GetEnv("AUTH_SIGNOUT", ""),

		TokenExpiresIn:   env.GetEnvInt("AUTH_TOKEN_EXPIRES_IN", 3600),          // 기본 1시간
		IDExpiresIn:      env.GetEnvInt("AUTH_ID_EXPIRES_IN", 3600),             // 기본 1시간
		RefreshExpiresIn: env.GetEnvInt("AUTH_REFRESH_EXPIRES_IN", 60*60*24*30), // 기본 30일
	}
}

func GetClaims(c *gin.Context) *Claims {
	claimsRaw, exists := c.Get("claims")
	if exists && claimsRaw != nil {
		if claims, ok := claimsRaw.(*Claims); ok {
			return claims
		}
	}
	return &Claims{Groups: []string{"Guest"}}
}

func generateState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// OAuth2 로그인 시작 핸들러
func (ctrl *UserController) Signin(c *gin.Context) {
	state := generateState()
	session := sessions.Default(c)
	session.Set("oauth_state", state)
	session.Save()

	signinURI := fmt.Sprintf("%s&state=%s", ctrl.SigninURI, state)
	c.Redirect(http.StatusFound, signinURI)
}

// OAuth2 로그인 콜백 핸들러
func (ctrl *UserController) SigninCallback(c *gin.Context) {
	state := c.Query("state")
	session := sessions.Default(c)
	expectedState := session.Get("oauth_state")
	if expectedState != state {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	code := c.Query("code")
	if code == "" {
		log.Printf("[WARN] no authorization code provided in callback")
		c.JSON(http.StatusBadRequest, gin.H{"error": "no authorization code provided"})
		return
	}

	tokenRes, err := ctrl.AuthModel.GetToken(c.Request.Context(), code)
	if err != nil {
		log.Printf("[ERROR] failed to get token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error"})
		return
	}

	// 쿠키 설정
	c.SetCookie("t", tokenRes.IDToken, ctrl.IDExpiresIn, "/", ctrl.Servername, true, true)
	c.SetCookie("r", tokenRes.RefreshToken, ctrl.RefreshExpiresIn, "/", ctrl.Servername, true, true)

	protectedUrl := fmt.Sprintf("https://%s/app/*", ctrl.Servername)
	signedCookies, err := ctrl.CDNModel.CreateSignedCookies(
		protectedUrl, time.Now().Add(time.Duration(ctrl.RefreshExpiresIn)*time.Second),
	)

	for name, value := range signedCookies {
		c.SetCookie(
			name,                  // 쿠키 이름 (CloudFront-Policy, CloudFront-Signature, CloudFront-Key-Pair-Id)
			value,                 // 쿠키 값
			ctrl.RefreshExpiresIn, // 만료(초, int): 기존 expires 변수 재사용 (예: 30일)
			"/",                   // 경로
			ctrl.Servername,       // 도메인 (ex: yourdomain.com)
			true,                  // Secure
			true,                  // HttpOnly (CloudFront는 HttpOnly 없어도 동작, 있지만 보안상 true 권장)
		)
	}

	c.Redirect(http.StatusFound, "/")
}

// OAuth2 로그아웃 핸들러
func (ctrl *UserController) Signout(c *gin.Context) {
	c.SetCookie("t", "", -1, "/", ctrl.Servername, true, true)
	c.SetCookie("r", "", -1, "/", ctrl.Servername, true, true)
	c.SetCookie("CloudFront-Key-Pair-Id", "", -1, "/", ctrl.Servername, true, true)
	c.SetCookie("CloudFront-Policy", "", -1, "/", ctrl.Servername, true, true)
	c.SetCookie("CloudFront-Signature", "", -1, "/", ctrl.Servername, true, true)
	c.Redirect(http.StatusFound, ctrl.SignoutURI)
}

// OAuth2 로그아웃 콜백 핸들러 (필요시 추가로직 구현)
func (ctrl *UserController) SignoutCallback(c *gin.Context) {
	c.Redirect(http.StatusFound, "/")
}

// 비밀번호 초기화 요청 핸들러
func (ctrl *UserController) PostForgot(c *gin.Context) {
	var req ForgotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[WARN] failed to parse request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	// 이메일 검증
	email := req.Email
	if email == "" {
		log.Printf("[WARN] email is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if len(email) > 200 {
		log.Printf("[WARN] email too long")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	validEmail, err := param.ValidEmail(email)
	if err != nil {
		log.Printf("[WARN] email error")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if !validEmail {
		log.Printf("[WARN] email is invalid")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	ctx := c.Request.Context()
	// 비밀번호 초기화 요청 처리
	ok, err := ctrl.AuthModel.PostForgot(ctx, email)
	if err != nil {
		log.Printf("[ERROR] failed to request forgot: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error"})
		return
	}
	if !ok {
		log.Printf("[WARN] forgot request failed for email: %s", email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to request forgot"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset initiated, check your email."})
}

// 내정보 조회 핸들러
func (ctrl *UserController) GetMyinfo(c *gin.Context) {
	claims := GetClaims(c)

	user := UsersItem{
		ID:     claims.ID,
		Name:   claims.Name,
		Email:  claims.Email,
		Groups: claims.Groups,
	}

	c.JSON(http.StatusOK, user)
}

var allowedOrderColumns = map[string]string{
	"created_at": "created_at",
	"name":       "name",
}

// GetUsers: 사용자 목록 조회 (Admin용)
func (ctrl *UserController) GetUsers(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "60")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		log.Printf("[WARN] invalid limit: %q (%v)", limitStr, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	pageStr := c.DefaultQuery("page", "1")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page <= 0 {
		log.Printf("[WARN] invalid page: %q (%v)", pageStr, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	order := c.DefaultQuery("order", "created_at")
	if _, exists := allowedOrderColumns[order]; !exists {
		log.Printf("[WARN] invalid order: %q", order)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	desc := strings.ToUpper(c.DefaultQuery("desc", "DESC"))
	if desc != "ASC" && desc != "DESC" {
		log.Printf("[WARN] invalid desc: %q", desc)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	search := c.DefaultQuery("search", "")
	if search != "" {
		valid, err := param.ValidTitleKR(search)
		if err != nil {
			log.Printf("[WARN] search validation error: %q (%v)", search, err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		if !valid {
			log.Printf("[WARN] invalid search value: %q", search)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
	}

	ctx := c.Request.Context()
	group := c.DefaultQuery("group", "")
	if group != "" {
		valid, err := param.ValidId(group)
		if err != nil {
			log.Printf("[WARN] group validation failed: %q (%v)", group, err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		if !valid {
			log.Printf("[WARN] invalid group value: %q", group)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		exists, err := ctrl.GroupModel.Exists(ctx, "users", group)
		if err != nil {
			log.Printf("[WARN] error checking group existence: %q (%v)", group, err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		if !exists {
			log.Printf("[WARN] group does not exist: %q", group)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
	}

	result, err := ctrl.UserModel.GetUsers(ctx, limit, page, order, desc, search, group)
	if err != nil {
		log.Printf("[ERROR] failed to get articles: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error: %v", err)})
		return
	}

	c.JSON(http.StatusOK, result)

}

// GetUser: 특정 사용자 조회 (Admin용)
func (ctrl *UserController) GetUser(c *gin.Context) {
	encodedId := c.Param("id")
	if encodedId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username required"})
		return
	}
	id, err := url.PathUnescape(encodedId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid username encoding"})
		return
	}
	if len(id) > 256 {
		log.Printf("[WARN] email too long")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	validEmail, err := param.ValidEmail(id)
	if err != nil {
		log.Printf("[WARN] email error")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if !validEmail {
		log.Printf("[WARN] email is invalid")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	ctx := c.Request.Context()
	result, err := ctrl.UserModel.GetUser(ctx, id)
	if err != nil {
		log.Printf("[ERROR] failed to get articles: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error"})
		return
	}

	c.JSON(http.StatusOK, result)
}

func (ctrl *UserController) PostUser(c *gin.Context) {
	var req PostUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[WARN] failed to parse request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	// 아이디 검증
	id := req.ID
	if id == "" {
		log.Printf("[WARN] id is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if len(id) > 256 {
		log.Printf("[WARN] id too long")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	validId, err := param.ValidEmail(id)
	if err != nil {
		log.Printf("[WARN] id error")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if !validId {
		log.Printf("[WARN] id is invalid")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	// 이름 검증
	name := req.Name
	if name == "" {
		log.Printf("[WARN] name is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if len(name) > 64 {
		log.Printf("[WARN] name too long")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	validName, err := param.ValidNameKR(name)
	if err != nil {
		log.Printf("[WARN] name error")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if !validName {
		log.Printf("[WARN] name is invalid")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	// 이메일 검증
	email := req.Email
	if email == "" {
		log.Printf("[WARN] email is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if len(email) > 256 {
		log.Printf("[WARN] email too long")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	validEmail, err := param.ValidEmail(email)
	if err != nil {
		log.Printf("[WARN] email error")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if !validEmail {
		log.Printf("[WARN] email is invalid")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ctx := c.Request.Context()
	claims := GetClaims(c)
	ctrl.AuthModel.PostUser(ctx, id, name, email)

	user, err := ctrl.AuthModel.GetUser(ctx, id)
	if err != nil {
		log.Printf("[ERROR] failed to get user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error"})
		return
	}

	_, err2 := ctrl.UserModel.PostUser(
		ctx, id, name, email, user.EmailVerified,
		user.Status, user.CreatedAt, user.UpdatedAt, user.DeletedAt,
		claims.ID, claims.Name,
	)
	if err2 != nil {
		log.Printf("[ERROR] failed to create user: %v", err2)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func (ctrl *UserController) PutUser(c *gin.Context) {
	var req PostUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[WARN] failed to parse request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	// 아이디 검증
	id := c.Param("id")
	if id == "" {
		log.Printf("[WARN] id is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if len(id) > 256 {
		log.Printf("[WARN] id too long")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	validId, err := param.ValidEmail(id)
	if err != nil {
		log.Printf("[WARN] id error")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if !validId {
		log.Printf("[WARN] id is invalid")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	// 이름 검증
	name := req.Name
	if name == "" {
		log.Printf("[WARN] name is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if len(name) > 64 {
		log.Printf("[WARN] name too long")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	validName, err := param.ValidNameKR(name)
	if err != nil {
		log.Printf("[WARN] name error")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if !validName {
		log.Printf("[WARN] name is invalid")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	// 이메일 검증
	email := req.Email
	if email == "" {
		log.Printf("[WARN] email is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if len(email) > 256 {
		log.Printf("[WARN] email too long")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	validEmail, err := param.ValidEmail(email)
	if err != nil {
		log.Printf("[WARN] email error")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if !validEmail {
		log.Printf("[WARN] email is invalid")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ctx := c.Request.Context()
	claims := GetClaims(c)
	ctrl.AuthModel.PutUser(ctx, id, name, email)

	user, err := ctrl.AuthModel.GetUser(ctx, id)
	if err != nil {
		log.Printf("[ERROR] failed to get user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error"})
		return
	}

	_, err2 := ctrl.UserModel.PutUser(
		ctx, id, name, email, user.EmailVerified,
		user.Status, user.UpdatedAt, claims.ID, claims.Name,
	)
	if err2 != nil {
		log.Printf("[ERROR] failed to update user: %v", err2)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user updated successfully"})
}

func (ctrl *UserController) SyncUser() {
	ctx := context.TODO()
	// 1) Cognito(인증 시스템)·DB 사용자 전량 로드
	authUsers, err := ctrl.AuthModel.AllUsers(ctx)
	if err != nil {
		log.Printf("failed to get users from auth provider: %v", err)
		return
	}
	dbUsers, err := ctrl.UserModel.AllUsers(ctx)
	if err != nil {
		log.Printf("failed to get users from database: %v", err)
		return
	}
	// 2) map[id]User 편의 구조로 변환
	authMap := make(map[string]UsersItem, len(authUsers.Items))
	for _, u := range authUsers.Items {
		authMap[u.ID] = u
	}
	dbMap := make(map[string]UsersItem, len(dbUsers.Items))
	for _, u := range dbUsers.Items {
		dbMap[u.ID] = u
	}
	// 3) 삽입·업데이트 대상 계산
	var toInsert, toUpdate []UsersItem
	for id, au := range authMap {
		if du, ok := dbMap[id]; !ok {
			toInsert = append(toInsert, au)
		} else if userDiff(au, du) { // 이름/메일/상태/verify 등 달라진 것
			toUpdate = append(toUpdate, au)
		}
		delete(dbMap, id) // dbMap 에 남는 건 “삭제 후보”
	}
	// 4) 배치 INSERT
	for _, u := range toInsert {
		if _, err := ctrl.UserModel.PostUser(
			ctx, u.ID, u.Name, u.Email, u.EmailVerified,
			u.Status, u.CreatedAt, u.UpdatedAt, u.DeletedAt,
			"SYSTEM", "시스템",
		); err != nil {
			log.Printf("failed to insert user %s: %v", u.ID, err)
		}
	}
	// 5) 배치 UPDATE
	for _, u := range toUpdate {
		if _, err := ctrl.UserModel.PutUser(
			ctx, u.ID, u.Name, u.Email, u.EmailVerified,
			u.Status, u.UpdatedAt, "SYSTEM", "시스템",
		); err != nil {
			log.Printf("failed to update user %s: %v", u.ID, err)
		}
	}
	// 6) 그룹 동기화 (삽입·업데이트 후)
	for _, u := range authUsers.Items {
		if _, err := ctrl.UserModel.SyncGroup(
			ctx, u.ID, u.Groups, "SYSTEM", "시스템",
		); err != nil {
			log.Printf("failed to sync groups for %s: %v", u.ID, err)
		}
	}
	// 7) (선택) Cognito 에는 없고 DB 에만 남은 계정 처리
	for orphanID := range dbMap { // dbMap 에 남아 있는 id = 삭제 후보
		// 여기서는 하드 삭제 대신 상태만 DELETED 로 두는 예
		if _, err := ctrl.UserModel.DeleteUser(
			ctx, orphanID, "SYSTEM", "시스템",
		); err != nil {
			log.Printf("failed to mark deleted %s: %v", orphanID, err)
		}
	}
	log.Println("UserController SyncUser() Complete!")
}

// ------------------------------------------------------------------
// userDiff 는 두 레코드의 “업데이트 필요 여부” 판정 함수
// 필요한 필드만 비교하면 됩니다.
func userDiff(a, b UsersItem) bool {
	if a.Name != b.Name ||
		a.Email != b.Email ||
		a.EmailVerified != b.EmailVerified ||
		a.Status != b.Status {
		return true
	}
	// 그룹 배열 비교는 SyncGroup 이 따로 처리하므로 생략
	return false
}
