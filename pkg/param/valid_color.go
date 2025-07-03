// parkjunwoo.com/microstral/pkg/param/valid_color.go
package param

import (
	"fmt"
	"regexp"
)

func init() {
	RegisterValidFunc(COLOR, ValidColor)
	RegisterValidFunc(RGB, ValidRGB)
	RegisterValidFunc(RGBA, ValidRGBA)
	RegisterValidFunc(HSL, ValidHSL)
	RegisterValidFunc(HSLA, ValidHSLA)
}

var (
	regexColor = regexp.MustCompile(`^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$`)
	regexRGB   = regexp.MustCompile(`^rgb\((\d{1,3}),(\d{1,3}),(\d{1,3})\)$`)
	regexRGBA  = regexp.MustCompile(`^rgba\((\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})\)$`)
	regexHSL   = regexp.MustCompile(`^hsl\((\d{1,3}),(\d{1,3})%,(\d{1,3})%\)$`)
	regexHSLA  = regexp.MustCompile(`^hsla\((\d{1,3}),(\d{1,3})%,(\d{1,3})%,(\d{1,3})\)$`)
)

// ValidColor은 문자열이 유효한 색상 코드인지 확인합니다.
func ValidColor(value string) (bool, error) {
	res := regexColor.MatchString(value)
	if !res {
		return false, fmt.Errorf("invalid color format")
	}
	return true, nil
}

// ValidRGB는 문자열이 유효한 RGB 색상 코드인지 확인합니다.
func ValidRGB(value string) (bool, error) {
	res := regexRGB.MatchString(value)
	if !res {
		return false, fmt.Errorf("invalid RGB color format")
	}
	return true, nil
}

// ValidRGBA는 문자열이 유효한 RGBA 색상 코드인지 확인합니다.
func ValidRGBA(value string) (bool, error) {
	res := regexRGBA.MatchString(value)
	if !res {
		return false, fmt.Errorf("invalid RGBA color format")
	}
	return true, nil
}

// ValidHSL는 문자열이 유효한 HSL 색상 코드인지 확인합니다.
func ValidHSL(value string) (bool, error) {
	res := regexHSL.MatchString(value)
	if !res {
		return false, fmt.Errorf("invalid HSL color format")
	}
	return true, nil
}

// ValidHSLA는 문자열이 유효한 HSLA 색상 코드인지 확인합니다.
func ValidHSLA(value string) (bool, error) {
	res := regexHSLA.MatchString(value)
	if !res {
		return false, fmt.Errorf("invalid HSLA color format")
	}
	return true, nil
}
