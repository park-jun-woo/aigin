// https://parkjunwoo.com/microstral/pkg/param/valid_network.go
package param

import (
	"fmt"
	"mime"
	"net"
	"net/url"
	"regexp"
)

func init() {
	RegisterValidFunc(URL, ValidURL)
	RegisterValidFunc(DOMAIN, ValidDomain)
	RegisterValidFunc(PATH, ValidPath)
	RegisterValidFunc(QUERY, ValidQuery)
	RegisterValidFunc(FRAGMENT, ValidFragment)
	RegisterValidFunc(SLUG, ValidSlug)
	RegisterValidFunc(FILE, ValidFile)
	RegisterValidFunc(MIME, ValidMimeType)
	RegisterValidFunc(IP, ValidIP)
	RegisterValidFunc(IPV4, ValidIPv4)
	RegisterValidFunc(IPV6, ValidIPv6)
	RegisterValidFunc(MAC, ValidMAC)
	RegisterValidFunc(UUID, ValidUUID)
}

var (
	domainRegex   = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
	pathRegex     = regexp.MustCompile(`^/[A-Za-z0-9\-\._~!$&'()*+,;=:@/]*$`)
	queryRegex    = regexp.MustCompile(`^[A-Za-z0-9\-\._~!$&'()*+,;=:@/?]*$`)
	fragmentRegex = regexp.MustCompile(`^[A-Za-z0-9\-\._~!$&'()*+,;=:@/?]*$`)
	slugRegex     = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	fileRegex     = regexp.MustCompile(`^[^\\/:*?"<>|\r\n]+$`)
	uuidRegex     = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// ValidURL은 문자열이 유효한 URL인지 확인합니다.
func ValidURL(value string) (bool, error) {
	u, err := url.ParseRequestURI(value)
	if err != nil {
		return false, fmt.Errorf("invalid URL: %v", err)
	}
	// 스킴과 호스트가 존재해야 한다고 가정
	if u.Scheme == "" || u.Host == "" {
		return false, fmt.Errorf("invalid URL: scheme or host is empty")
	}
	return true, nil
}

// ValidDomain은 문자열이 유효한 도메인인지 확인합니다.
// - 전체 길이 255자 이하
// - 각 라벨은 알파벳/숫자로 시작/끝나며, 중간에 '-' 허용
// - 라벨 사이를 '.'으로 구분
func ValidDomain(value string) (bool, error) {
	if len(value) == 0 {
		return false, fmt.Errorf("domain is empty")
	}
	if len(value) > 255 {
		return false, fmt.Errorf("domain length exceeds 255 characters: %s", value)
	}

	// 도메인 라벨 검증용 정규식:
	// - 라벨은 알파벳/숫자로 시작할 수 있음
	// - 중간에는 알파벳/숫자/'-' 가능
	// - 라벨은 알파벳/숫자로 끝남
	if !domainRegex.MatchString(value) {
		return false, fmt.Errorf("invalid domain format: %s", value)
	}

	return true, nil
}

// ValidPath는 문자열이 URL 경로(path)로 사용 가능한지 간단히 확인합니다.
// - '/'로 시작
// - 공백, 제어문자 등은 허용하지 않는다고 가정(필요에 따라 조정)
func ValidPath(value string) (bool, error) {
	if len(value) == 0 {
		return false, fmt.Errorf("path is empty")
	}
	// URL path에 허용 가능한 문자를 정규식으로 제한
	// 여기서는 예시로 [A-Za-z0-9\-\._~!$&'()*+,;=:@/] 조합만 허용
	if !pathRegex.MatchString(value) {
		return false, fmt.Errorf("invalid path: %s", value)
	}
	return true, nil
}

// ValidQuery는 문자열이 URL 쿼리(query)로 사용 가능한지 간단히 확인합니다.
// - 일반적으로 쿼리는 ?, &, =, 알파벳, 숫자 등 다양한 문자를 포함할 수 있습니다.
// - 실제로는 URL 인코딩 여부 등을 체크해야 할 수도 있지만, 여기서는 간단히 정규식으로만 확인합니다.
func ValidQuery(value string) (bool, error) {
	// 빈 문자열(쿼리 없음)도 허용하는 경우가 있으니 상황에 맞게 처리
	if len(value) == 0 {
		// 쿼리가 없음을 허용한다면 true 반환
		return true, nil
	}
	// 예시로 [A-Za-z0-9\-\._~!$&'()*+,;=:@/?] 조합만 허용(공백 등은 허용 X)
	if !queryRegex.MatchString(value) {
		return false, fmt.Errorf("invalid query: %s", value)
	}
	return true, nil
}

// ValidFragment는 문자열이 URL 프래그먼트(fragment)로 사용 가능한지 간단히 확인합니다.
func ValidFragment(value string) (bool, error) {
	// 빈 문자열(프래그먼트 없음)도 허용하는 경우가 있으니 상황에 맞게 처리
	if len(value) == 0 {
		return true, nil
	}
	// 예시로 [A-Za-z0-9\-\._~!$&'()*+,;=:@/?] 조합만 허용
	if !fragmentRegex.MatchString(value) {
		return false, fmt.Errorf("invalid fragment: %s", value)
	}
	return true, nil
}

// ValidSlug는 문자열이 게시물 식별 등에 사용되는 슬러그로서 유효한지 확인합니다.
// - 여기서는 소문자 알파벳, 숫자, 하이픈(-)만 허용
// - 시작/끝에 하이픈이 오는 것은 허용하지 않는다고 가정(필요시 조정)
func ValidSlug(value string) (bool, error) {
	if len(value) == 0 {
		return false, fmt.Errorf("slug is empty")
	}
	if !slugRegex.MatchString(value) {
		return false, fmt.Errorf("invalid slug: %s", value)
	}
	return true, nil
}

// ValidFile은 문자열이 파일 이름으로서 유효한지 확인합니다.
// - Windows 상에서 예약된 문자(\/:*?"<>|) 및 제어문자 등을 허용하지 않는다고 가정
// - 실제로 OS별로 규칙이 다를 수 있으므로 필요한 규칙에 맞게 수정해야 합니다.
func ValidFile(value string) (bool, error) {
	if len(value) == 0 {
		return false, fmt.Errorf("file name is empty")
	}
	// 예약된 문자: \ / : * ? " < > | 및 제어문자(\r, \n 등) 금지
	if !fileRegex.MatchString(value) {
		return false, fmt.Errorf("invalid file name: %s", value)
	}
	// Windows에서는 '.', ' '로 끝나면 안 되는 등 추가 규칙도 있으나 생략
	// '.' 또는 '..'인지도 검사 가능
	if value == "." || value == ".." {
		return false, fmt.Errorf("file name cannot be '.' or '..'")
	}
	return true, nil
}

// ValidMimeType은 문자열이 유효한 MIME 타입인지 확인합니다.
// - Go 표준 라이브러리 mime.ParseMediaType를 이용하여 파싱해보고 에러가 없는지 확인합니다.
func ValidMimeType(value string) (bool, error) {
	_, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false, fmt.Errorf("invalid MIME type: %v", err)
	}
	return true, nil
}

// ValidIP는 문자열이 유효한 IP 주소인지 확인합니다.
func ValidIP(value string) (bool, error) {
	ip := net.ParseIP(value)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", value)
	}
	return true, nil
}

// ValidIPv4는 문자열이 유효한 IPv4 주소인지 확인합니다.
func ValidIPv4(value string) (bool, error) {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return false, fmt.Errorf("invalid IPv4 address: %s", value)
	}
	return true, nil
}

// ValidIPv6는 문자열이 유효한 IPv6 주소인지 확인합니다.
func ValidIPv6(value string) (bool, error) {
	ip := net.ParseIP(value)
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return false, fmt.Errorf("invalid IPv6 address: %s", value)
	}
	return true, nil
}

// ValidMAC는 문자열이 유효한 MAC 주소인지 확인합니다.
// - net.ParseMAC 사용
func ValidMAC(value string) (bool, error) {
	_, err := net.ParseMAC(value)
	if err != nil {
		return false, fmt.Errorf("invalid MAC address: %v", err)
	}
	return true, nil
}

// ValidUUID는 문자열이 유효한 UUID(v4 등)인지 확인합니다.
// - 간단히 정규식 사용. 필요에 따라 UUID 버전도 체크 가능.
func ValidUUID(value string) (bool, error) {
	if !uuidRegex.MatchString(value) {
		return false, fmt.Errorf("invalid UUID: %s", value)
	}
	return true, nil
}
