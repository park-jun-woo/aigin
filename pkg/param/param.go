// parkjunwoo.com/microstral/pkg/param/param.go
package param

import (
	"fmt"
	"regexp"

	"parkjunwoo.com/microstral/pkg/flag"
)

type Param struct {
	Name     string
	Default  string
	Type     uint32
	Flag     uint64
	Required bool
	Regex    *regexp.Regexp
}

func (p *Param) Validate(input string) (bool, error) {
	// Required=false 이면서 input이 비어 있다면 통과
	if input == "" && !p.Required {
		return true, nil
	}

	// v.Type으로 먼저 분기
	switch p.Type {
	// FLAG 기반 검증
	case FLAG:
		// 숫자 허용 여부
		if (p.Flag & flag.NUM) != 0 {

		}

		if (p.Flag & flag.HANGUL) != 0 {

		}

		return true, nil
	// 사용자 정의 패턴의 정규식 검증
	case REGEX:
		// 패턴 정의가 안되어 있으면 false
		if p.Regex == nil {
			return false, fmt.Errorf("no pattern defined")
		}

		// 정규식 검증
		re := p.Regex.MatchString(input)
		if !re {
			return false, fmt.Errorf("invalid input: %s", input)
		}

		// 정규식 통과
		return true, nil
	default:
		// Type에 따른 검증 함수 탐색
		fn, ok := validFuncs[p.Type]
		if !ok {
			return false, fmt.Errorf("undefined parameter type %d", p.Type)
		}

		// 검증 함수 실행
		result, err := fn(input)
		if err != nil {
			return false, err
		}

		// 결과 반환
		return result, nil
	}

}
