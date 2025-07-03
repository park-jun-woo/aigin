// parkjunwoo.com/microstral/pkg/flag/number.go
package flag

import "strconv"

// ValidInt는 문자열이 유효한 정수인지 확인합니다.
func FlagValidInt(value string) bool {
	_, err := strconv.Atoi(value)
	return err == nil
}

// ValidNumber는 문자열이 유효한 실수(부동 소수점 숫자)인지 확인합니다.
func FlagValidNumber(value string) bool {
	_, err := strconv.ParseFloat(value, 64)
	return err == nil
}
