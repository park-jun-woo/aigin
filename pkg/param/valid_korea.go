// parkjunwoo.com/microstral/pkg/param/valid_korea.go
package param

import (
	"fmt"
	"regexp"
)

func init() {
	RegisterValidFunc(NAME_KR, ValidNameKR)
	RegisterValidFunc(TITLE_KR, ValidTitleKR)
	RegisterValidFunc(SSN_KR, ValidSSNKR)
	RegisterValidFunc(RRN_KR, ValidRRNKR)
	RegisterValidFunc(BRN_KR, ValidBRNKR)
	RegisterValidFunc(PCC_KR, ValidPCCKR)
	RegisterValidFunc(PASSPORT_KR, ValidPassportKR)
	RegisterValidFunc(DRIVING_LICENSE_KR, ValidDLKR)
	RegisterValidFunc(ZIPCODE_KR, ValidZipcodeKR)
}

var (
	regNameKR       = regexp.MustCompile(`^[가-힣a-zA-Z0-9 .-_]+$`)
	regTitleKR      = regexp.MustCompile(`^[가-힣a-zA-Z0-9 .,!?\[\]\(\)_\-@&/|$%*+~^:={}'"]+$`)
	regexSSNKR      = regexp.MustCompile(`^(\d{6})-?[1-4]{1}\d{6}$`)
	regexRRNKR      = regexp.MustCompile(`^(\d{6})-?[5-8]{1}\d{6}$`)
	regexBRNKR      = regexp.MustCompile(`^(\d{3})-?(\d{2})-?(\d{5})$`)
	regexPCCKR      = regexp.MustCompile(`^P\d{12}$`)
	regexPassportKR = regexp.MustCompile(`^[A-Z]{1}[0-9]{8}$`)
	regexDLKR       = regexp.MustCompile(`^\d{2}-?\d{2}-?\d{6}-?\d{2}$`)
	regexZipcodeKR  = regexp.MustCompile(`^\d{5}$`)
)

// ValidNameKR은 한국 이름 형식이 맞는지 확인합니다.
func ValidNameKR(value string) (bool, error) {
	return regNameKR.MatchString(value), nil
}

// ValidTitleKR은 한국 제목 형식이 맞는지 확인합니다.
func ValidTitleKR(value string) (bool, error) {
	return regTitleKR.MatchString(value), nil
}

// ValidSSN은 주민등록번호 형식이 맞는지 확인합니다.
func ValidSSNKR(value string) (bool, error) {
	if !regexSSNKR.MatchString(value) {
		return false, fmt.Errorf("invalid social security number format")
	}
	return true, nil
}

// ValidRRN은 외국인등록번호 형식이 맞는지 확인합니다.
func ValidRRNKR(value string) (bool, error) {
	if !regexRRNKR.MatchString(value) {
		return false, fmt.Errorf("invalid resident registration number format")
	}
	return true, nil
}

// ValidBN은 사업자등록번호 형식이 맞는지 확인합니다.
func ValidBRNKR(value string) (bool, error) {
	if !regexBRNKR.MatchString(value) {
		return false, fmt.Errorf("invalid business registration number format")
	}
	return true, nil
}

// ValidPCC은 개인통관고유부호 형식이 맞는지 확인합니다.
func ValidPCCKR(value string) (bool, error) {
	if !regexPCCKR.MatchString(value) {
		return false, fmt.Errorf("invalid personal customs code format")
	}
	return true, nil
}

// ValidDrivingLicense은 운전면허번호 형식이 맞는지 확인합니다.
func ValidDLKR(value string) (bool, error) {
	if !regexDLKR.MatchString(value) {
		return false, fmt.Errorf("invalid driving license format")
	}
	return true, nil
}

// ValidPassport
// - 여권번호 (대문자 + 숫자 포함 9글자)
func ValidPassportKR(value string) (bool, error) {
	if !regexPassportKR.MatchString(value) {
		return false, fmt.Errorf(
			"invalid passport format: must be 9 chars, contain uppercase letters and digits",
		)
	}
	return true, nil
}

// ValidZipcode은 우편번호 형식이 맞는지 확인합니다.
func ValidZipcodeKR(value string) (bool, error) {
	if !regexZipcodeKR.MatchString(value) {
		return false, fmt.Errorf("invalid zipcode format")
	}
	return true, nil
}
