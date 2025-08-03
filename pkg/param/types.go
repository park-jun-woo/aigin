// parkjunwoo.com/aigin/pkg/param/types.go
package param

import "math"

// 문자열 관련 파라미터 타입들
const (
	FLAG  = 0              // 플래그 사용
	REGEX = math.MaxUint32 // 별도의 정규식으로 검증, uint32 범위 안에서 가장 큰 값을 “정규식 전용”으로 사용하여 충돌을 원천적으로 차단
)

// 전화번호 관련 파라미터 타입들
// 1= NANP (포괄), 7=러시아, ...
// 8001=미국(+1), 8002=캐나다(+1) ...
// 9998=로컬 형식, 9999=E.164 형식
const (
	PHONE_NANP = 1         // 북미 전화번호
	PHONE_RU   = 7         // 러시아 전화번호
	PHONE_FR   = 33        // 프랑스 전화번호
	PHONE_ES   = 34        // 스페인 전화번호
	PHONE_IT   = 39        // 이탈리아 전화번호
	PHONE_GB   = 44        // 영국 전화번호
	PHONE_DE   = 49        // 독일 전화번호
	PHONE_BR   = 55        // 브라질 전화번호
	PHONE_MY   = 60        // 말레이시아 전화번호
	PHONE_AU   = 61        // 호주 전화번호
	PHONE_ID   = 62        // 인도네시아 전화번호
	PHONE_PH   = 63        // 필리핀 전화번호
	PHONE_TH   = 66        // 태국 전화번호
	PHONE_JP   = 81        // 일본 전화번호
	PHONE_KR   = 82        // 한국 전화번호
	PHONE_VN   = 84        // 베트남 전화번호
	PHONE_CN   = 86        // 중국 전화번호
	PHONE_TR   = 90        // 터키 전화번호
	PHONE_IN   = 91        // 인도 전화번호
	PHONE_PK   = 92        // 파키스탄 전화번호
	PHONE_IR   = 98        // 이란 전화번호
	PHONE_BD   = 880       // 방글라데시 전화번호
	PHONE_JO   = 962       // 요르단 전화번호
	PHONE_KW   = 965       // 쿠웨이트 전화번호
	PHONE_SA   = 966       // 사우디아라비아 전화번호
	PHONE_AE   = 971       // 아랍에미리트 전화번호
	PHONE_IL   = 972       // 이스라엘 전화번호
	PHONE_AZ   = 994       // 아제르바이잔 전화번호
	PHONE_UZ   = 998       // 우즈베키스탄 전화번호
	MOBILE_KR  = 1000 + 82 // 한국 휴대전화번호
	PHONE_US   = 9001      // 미국(+1) 전화번호
	PHONE_CA   = 9002      // 캐나다(+1) 전화번호
	PHONE      = 9998      // 국가별 전화번호 하이픈/괄호 등 자유로운 로컬 형식
	PHONE_E164 = 9999      // 국제 전화번호 형식 (E.164), +붙여서 최대 15자리 숫자
)

// 시간/날짜 관련 파라미터 타입들
const (
	DATE      = iota + 10001 // 날짜만 2025-02-21
	TIME                     // 시간만 14:30:00
	DATE_TIME                // 날짜와 시간 2025-02-21 14:30:00
	UNIX_TIME                // 1970년 1월 1일 00:00:00부터의 초
	UTC_TIME                 // UTC 시간대의 날짜와 시간 (RFC3339) 2025-02-21T14:30:00Z
	DURATION                 // 시간 간격 (예: 1h30m, 2h, 30m, 1h 등)
)

// 컨텐츠 관련 파라미터 타입들
const (
	HTML     = iota + 10101 // HTML 코드 문자열
	JSON                    // JSON 문자열
	XML                     // XML 문자열
	YAML                    // YAML 문자열
	CSV                     // CSV 문자열
	BASE64                  // Base64 인코딩된 문자열
	JWT                     // JWT 토큰
	MARKDOWN                // Markdown 코드 문자열
)

// 네트워크 관련 파라미터 타입들
const (
	URL      = iota + 10201 // URL 주소 예: http://domain.com
	DOMAIN                  // 도메인 주소 예: domain.com
	PATH                    // URL 경로 예: /path/to/resource
	QUERY                   // URL 쿼리 문자열 예: ?key=value&key2=value2
	FRAGMENT                // URL Fragment 문자열 예: #section
	SLUG                    // URL Slug 예: my-article-title
	FILE                    // 파일 이름 예: my-file.txt
	MIME                    // MIME 타입 예: application/json
	IP                      // IP 주소 (IPv4, IPv6 모두 허용)
	IPV4                    // IPv4 주소
	IPV6                    // IPv6 주소
	MAC                     // MAC 주소
	UUID                    // UUID (RFC4122)
)

// 색상 관련 파라미터 타입들
const (
	COLOR = iota + 10401 // 16진수 색상 코드 예: #FF0000
	RGB                  // RGB 색상 코드 예: rgb(255, 0, 0)
	RGBA                 // RGBA 색상 코드 예: rgba(255, 0, 0, 0.5)
	HSL                  // HSL 색상 코드 예: hsl(0, 100%, 50%)
	HSLA                 // HSLA 색상 코드 예: hsla(0, 100%, 50%, 0.5)
)

// 기타
const (
	ID = iota + 10501 // 아이디
)

// 개인정보 파라미터 타입들
const (
	PASSWORD        = iota + 11001 // 비밀번호 (특수문자, 대소문자, 숫자 포함 8글자 이상)
	PASSWORD_STRONG                // 강력한 비밀번호 (특수문자, 대소문자, 숫자 포함 12글자 이상)
	EMAIL                          // 이메일 주소 예: mail@domain.com
	CREDITCARD                     // 신용카드 번호 예: 1234-5678-9012-3456
)

//대한민국 관련 파라미터 타입들
const (
	NAME_KR            = iota + 12001 // 이름 예: "홍길동"
	TITLE_KR                          // 제목 예: "안녕하세요"
	SSN_KR                            // 주민등록번호 예: 123456-1234567
	RRN_KR                            // 외국인등록번호 예: 123456-1234567
	BRN_KR                            // 사업자등록번호 예: 123-45-67890
	PCC_KR                            // 개인통관고유부호
	PASSPORT_KR                       // 여권 번호 예: AB1234567
	DRIVING_LICENSE_KR                // 운전면허번호 예: 11-19-123456-01
	ZIPCODE_KR                        // 우편번호 예: 12345
)
