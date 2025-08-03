// parkjunwoo.com/aigin/pkg/param/valid_time.go
package param

import (
	"strconv"
	"time"
)

func init() {
	RegisterValidFunc(DATE, ValidDate)
	RegisterValidFunc(TIME, ValidTime)
	RegisterValidFunc(DATE_TIME, ValidDateTime)
	RegisterValidFunc(UNIX_TIME, ValidUnixTime)
	RegisterValidFunc(UTC_TIME, ValidUTCTime)
	RegisterValidFunc(DURATION, ValidDuration)
}

// ValidDate는 문자열이 "2006-01-02" 형식의 유효한 날짜인지 확인합니다.
func ValidDate(value string) (bool, error) {
	_, err := time.Parse("2006-01-02", value)
	return err == nil, err
}

// ValidTime은 문자열이 "15:04:05" 형식의 유효한 시간인지 확인합니다.
func ValidTime(value string) (bool, error) {
	_, err := time.Parse("15:04:05", value)
	return err == nil, err
}

// ValidDateTime은 문자열이 "2006-01-02T15:04:05" 형식의 유효한 날짜시간인지 확인합니다.
// (필요에 따라 다른 형식으로 변경할 수 있습니다.)
func ValidDateTime(value string) (bool, error) {
	_, err := time.Parse("2006-01-02T15:04:05", value)
	return err == nil, err
}

// ValidUnixTime은 문자열이 유효한 Unix 타임스탬프(정수)인지 확인합니다.
func ValidUnixTime(value string) (bool, error) {
	_, err := strconv.ParseInt(value, 10, 64)
	return err == nil, err
}

// (신규) RFC3339(ISO8601 유사) 형식 날짜시간 검증
//   - 예: "2006-01-02T15:04:05Z07:00" / "2023-02-19T03:45:00Z" 등
func ValidUTCTime(value string) (bool, error) {
	_, err := time.Parse(time.RFC3339, value)
	return err == nil, err
}

// ValidDuration은 문자열이 유효한 시간 간격(예: "1h30m")인지 확인합니다.
func ValidDuration(value string) (bool, error) {
	_, err := time.ParseDuration(value)
	return err == nil, err
}
