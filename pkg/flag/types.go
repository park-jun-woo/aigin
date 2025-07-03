// https://parkjunwoo.com/microstral/pkg/flag/types.go
package flag

// 기본적인 숫자/불리언 파라미터 타입들
const (
	BOOL = 1 << 0      // 직접 지정된 값
	UINT = 1 << 1      // 양의 정수만
	INT  = UINT | BOOL // 일반적인 int (음수 포함)
	UNUM = 1 << 2      // 양의 실수만
	NUM  = UNUM | BOOL // 실수 (음수 포함)
	OCT  = 1 << 3      // 8진수 문자열
	HEX  = 1 << 4      // 16진수 문자열
)

// 문자열 구성에 대한 비트마스크/플래그
const (
	SPCIAL       = 1 << (iota + 5) // 키보드 자판의 특수문자만  허용
	SPCIAL_EXT                     // 확장 특수문자까지 허용
	EMOJI                          // 이모지만 허용
	UPPER                          // 대문자만 허용
	LOWER                          // 소문자만 허용
	LATIN                          // ISO-8859-1 문자셋만 허용
	LATIN_EXT                      // ISO-8859-1 확장 문자셋만 허용
	HEBREW                         // 히브리 문자셋만 허용
	CYRILLIC                       // 키릴 문자셋만 허용
	GREEK                          // 그리스 문자셋만 허용
	ARABIC                         // 아랍 문자셋만 허용
	HANZI                          // 한자만 허용
	HANZI_SIMPLE                   // 간체자만 허용
	HANGUL                         // 한글만 허용
	KATAKANA                       // 가타카나만 허용
	HIRAGANA                       // 히라가나만 허용
	DEVANAGARI                     // 데바나가리 문자셋만 허용
)

// 문자열 구성에 대한 조합된 플래그
const (
	ALPHA     = UPPER | LOWER        // 대+소문자만 허용
	LATIN_ALL = LATIN | LATIN_EXT    // ISO-8859-1 전체 문자셋 허용
	HANZI_ALL = HANZI | HANZI_SIMPLE // 한자 전체 허용
	JAPANESE  = KATAKANA | HIRAGANA  // 일본어 문자셋만 허용

	ALPHA_NUM                = ALPHA | NUM                   // 대+소문자 | 숫자
	HANGUL_NUM               = HANGUL | NUM                  // 한글 | 숫자
	ALPHA_HANGUL_NUM         = ALPHA | HANGUL | NUM          // 대+소문자 | 한글 | 숫자
	ALPHA_NUM_SPECIAL        = ALPHA | NUM | SPCIAL          // 대+소문자 | 숫자 | 특수문자
	HANGUL_NUM_SPECIAL       = HANGUL | NUM | SPCIAL         // 한글 | 숫자 | 특수문자
	ALPHA_HANGUL_NUM_SPECIAL = ALPHA | HANGUL | NUM | SPCIAL // 대+소문자 | 한글 | 숫자 | 특수문자
)
