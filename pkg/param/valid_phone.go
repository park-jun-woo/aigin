// parkjunwoo.com/microstral/pkg/param/valid_phone.go
package param

import (
	"fmt"
	"regexp"
	"unicode"
)

func init() {
	RegisterValidFunc(PHONE_KR, ValidPhoneKR)
	RegisterValidFunc(PHONE, ValidPhone)
	RegisterValidFunc(PHONE_E164, ValidPhoneE164)
}

var (
	regexPhoneKR   = regexp.MustCompile(`^(?:\+?82[- ]?)?0\d{1,2}-?\d{3,4}-?\d{4}$`)
	regexPhone     = regexp.MustCompile(`^(\+?\d{1,3})?(-?\d+){1,4}$`)
	regexPhoneE164 = regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	regexMobileKR  = regexp.MustCompile(`^(\+?82-?|0)1[0-9]{1}-?[0-9]{3,4}-?[0-9]{4}$`)
)

// 한국 전화번호 형식 검증
//   - 국가코드(+82, 82, 010) 선택적
func ValidPhoneKR(value string) (bool, error) {
	if !regexPhoneKR.MatchString(value) {
		return false, fmt.Errorf("invalid phone number format")
	}
	return true, nil
}

// ValidPhone 은
// 1) 국가코드 유무(+1~3자리까지) 선택 가능
// 2) 하이픈은 0~3번까지 임의 위치
// 3) 전체 숫자 6~15자리
// 4) 공백/괄호 등 불허
// 등의 조건으로 전 세계 다양한 전화번호 형식을 폭넓게 허용하는 정규식 검증입니다.
//
// *실제 존재하는 번호인지는 검증하지 않습니다*.
func ValidPhone(value string) (bool, error) {
	// 1. 정규식으로 "형태"부터 검사
	//    예: +82-10-1234-5678, 010-1234-5678, 123456, etc.
	if !regexPhone.MatchString(value) {
		return false, fmt.Errorf("invalid phone number format")
	}

	// 2. 전체 문자열에서 숫자만 세어 길이가 6 ~ 15인지 확인
	countDigits := 0
	for _, r := range value {
		if unicode.IsDigit(r) {
			countDigits++
		}
	}

	if countDigits < 6 || countDigits > 15 {
		return false, fmt.Errorf("invalid phone number length")
	}

	return true, nil
}

// (신규) 전화번호 국제 형식(E.164) 검증
//   - 최대 15자리 숫자, 선택적 "+"로 시작.
//   - 엄격하게 E.164만 통과시키고 싶다면 "^\\+?[1-9]\\d{1,14}$" 식을 주로 사용합니다.
//   - 다만, 이것은 로컬 전화번호(0으로 시작하는)까지는 포함하지 못할 수 있습니다.
func ValidPhoneE164(value string) (bool, error) {
	result := regexPhoneE164.MatchString(value)
	if !result {
		return false, fmt.Errorf("invalid E.164 phone number")
	}
	return true, nil
}

// (신규) 한국 휴대폰 번호 형식 검증
//   - 국가코드(+82, 82, 010) 선택적
//   - 010-1234-5678, 01012345678, +82-10-1234-5678, 011-123-4567, etc.
func ValidMobileKR(value string) (bool, error) {
	if !regexMobileKR.MatchString(value) {
		return false, fmt.Errorf("invalid mobile phone number format")
	}
	return true, nil
}
