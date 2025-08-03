// parkjunwoo.com/aigin/pkg/param/valid_personal.go
package param

import (
	"fmt"
	"net/mail"
	"regexp"
	"unicode"
)

func init() {
	RegisterValidFunc(EMAIL, ValidEmail)
	RegisterValidFunc(PASSWORD, ValidNormalPassword)
	RegisterValidFunc(PASSWORD_STRONG, ValidStrongPassword)
	RegisterValidFunc(CREDITCARD, ValidCreditcard)
}

var (
	regexName       = regexp.MustCompile(`^[가-힣a-zA-Z0-9 ]+$`)
	regexPassword   = regexp.MustCompile(`^[A-Za-z0-9!@#$%^&*()_+\-=\\|{}\[\]:;"'<>,.?/~` + "`" + `]+$`)
	regexCreditcard = regexp.MustCompile(`^[0-9]{4}-?[0-9]{4}-?[0-9]{4}-?[0-9]{4}$`)
)

func ValidName(value string) (bool, error) {
	return regexName.MatchString(value), nil
}

// ValidEmail - 문자열이 유효한 이메일 주소인지 확인
func ValidEmail(value string) (bool, error) {
	_, err := mail.ParseAddress(value)
	return err == nil, err
}

// - 특수문자, 대소문자, 숫자 포함 8글자 이상
func ValidNormalPassword(value string) (bool, error) {
	return ValidPassword(value, 8)
}

// - 특수문자, 대소문자, 숫자 포함 12글자 이상
func ValidStrongPassword(value string) (bool, error) {
	return ValidPassword(value, 12)
}

// ValidCreditcard
// - 신용카드번호 (숫자 16자리)
func ValidCreditcard(value string) (bool, error) {
	if !regexCreditcard.MatchString(value) {
		return false, fmt.Errorf(
			"invalid credit card number format: must be 16-digit numeric",
		)
	}
	return true, nil
}

// ValidPassword
// - 특수문자, 대소문자, 숫자 포함 8글자 이상
func ValidPassword(value string, ln int) (bool, error) {
	// 길이 검사 (예: 8글자 이상)
	if len(value) < ln {
		return false, fmt.Errorf("password must be at least %d characters long", ln)
	}
	// 정규식으로 (특수문자, 대소문자, 숫자) 포함 여부 검사
	if !regexPassword.MatchString(value) {
		return false, fmt.Errorf("password contains invalid characters")
	}

	// 대문자, 소문자, 숫자, 특수문자 포함 여부를 코드에서 확인
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range value {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case !unicode.IsLetter(char) && !unicode.IsNumber(char):
			hasSpecial = true
		}
	}

	// 모든 조건이 충족되어야 함
	if !hasUpper {
		return false, fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return false, fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return false, fmt.Errorf("password must contain at least one digit")
	}
	if !hasSpecial {
		return false, fmt.Errorf("password must contain at least one special character")
	}

	return true, nil
}
