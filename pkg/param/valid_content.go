// parkjunwoo.com/aigin/pkg/param/valid_content.go
package param

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/gomarkdown/markdown"
	"github.com/microcosm-cc/bluemonday"
	"golang.org/x/net/html"
	"gopkg.in/yaml.v3"
)

func init() {
	RegisterValidFunc(ID, ValidId)
	RegisterValidFunc(HTML, ValidHTML)
	RegisterValidFunc(JSON, ValidJSON)
	RegisterValidFunc(XML, ValidXML)
	RegisterValidFunc(YAML, ValidYAML)
	RegisterValidFunc(CSV, ValidCSV)
	RegisterValidFunc(BASE64, ValidBASE64)
	RegisterValidFunc(JWT, ValidJWT)
	RegisterValidFunc(MARKDOWN, ValidMarkdown)
}

var (
	regId = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
)

// ValidId는 아이디 형식이 맞는지 확인합니다.
func ValidId(value string) (bool, error) {
	return regId.MatchString(value), nil
}

// ValidHTML은 문자열이 유효한 HTML인지 확인합니다.
// - golang.org/x/net/html 패키지를 사용하여 파싱 시도
func ValidHTML(value string) (bool, error) {
	if len(value) == 0 {
		return false, fmt.Errorf("empty HTML string")
	}
	_, err := html.Parse(strings.NewReader(value))
	if err != nil {
		return false, fmt.Errorf("invalid HTML: %v", err)
	}
	return true, nil
}

// ValidJSON은 문자열이 유효한 JSON인지 확인합니다.
// - encoding/json.Unmarshal을 이용하여 에러 여부 검사
func ValidJSON(value string) (bool, error) {
	if len(value) == 0 {
		return false, fmt.Errorf("empty JSON string")
	}
	var js json.RawMessage
	if err := json.Unmarshal([]byte(value), &js); err != nil {
		return false, fmt.Errorf("invalid JSON: %v", err)
	}
	return true, nil
}

// ValidXML은 문자열이 유효한 XML인지 확인합니다.
// - encoding/xml.Unmarshal을 이용하여 에러 여부 검사
// - 단, 루트 엘리먼트가 여러 개인 경우 등 특정 상황은 추가적으로 처리 필요
func ValidXML(value string) (bool, error) {
	if len(value) == 0 {
		return false, fmt.Errorf("empty XML string")
	}
	var v interface{}
	if err := xml.Unmarshal([]byte(value), &v); err != nil {
		return false, fmt.Errorf("invalid XML: %v", err)
	}
	return true, nil
}

// ValidYAML은 문자열이 유효한 YAML인지 확인합니다.
// - gopkg.in/yaml.v3 라이브러리를 이용하여 파싱 시도
func ValidYAML(value string) (bool, error) {
	if len(value) == 0 {
		return false, fmt.Errorf("empty YAML string")
	}
	var data interface{}
	if err := yaml.Unmarshal([]byte(value), &data); err != nil {
		return false, fmt.Errorf("invalid YAML: %v", err)
	}
	return true, nil
}

// ValidCSV는 문자열이 유효한 CSV인지 확인합니다.
// - encoding/csv.Reader로 전체 라인을 파싱하면서 에러가 발생하는지 확인
func ValidCSV(value string) (bool, error) {
	if len(value) == 0 {
		return false, fmt.Errorf("empty CSV string")
	}
	r := csv.NewReader(strings.NewReader(value))
	for {
		_, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, fmt.Errorf("invalid CSV: %v", err)
		}
	}
	return true, nil
}

// ValidBASE64는 문자열이 유효한 BASE64 인코딩인지 확인합니다.
// - base64.StdEncoding 또는 base64.RawStdEncoding.DecodeString으로 검사
func ValidBASE64(value string) (bool, error) {
	if len(value) == 0 {
		return false, fmt.Errorf("empty BASE64 string")
	}
	_, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		// 일부 응용에서는 URL-safe Base64, Raw Base64 등을 사용할 수도 있으므로
		// 필요하다면 다른 디코더도 시도해볼 수 있습니다.
		return false, fmt.Errorf("invalid BASE64: %v", err)
	}
	return true, nil
}

// ValidJWT는 문자열이 유효한 JWT(JSON Web Token) 구조인지 간단히 검사합니다.
// - header.payload.signature 형태로 3개 파트
// - 각 파트가 base64 URL-safe 형태로 디코딩 가능한지
// - 실제 서명 검증이나 클레임(만료시간, issuer 등) 검증은 포함되지 않음
func ValidJWT(value string) (bool, error) {
	if len(value) == 0 {
		return false, fmt.Errorf("empty JWT string")
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid JWT format: needs 3 parts (header.payload.signature)")
	}
	for _, p := range parts {
		// JWT는 base64 URL-safe 인코딩을 사용하므로 RawURLEncoding 사용
		if _, err := base64.RawURLEncoding.DecodeString(p); err != nil {
			return false, fmt.Errorf("invalid JWT part: %v", err)
		}
	}
	return true, nil
}

// ValidMarkdown은 문자열이 유효한 마크다운인지 간단히 확인합니다.
func ValidMarkdown(value string) (bool, error) {
	html := markdown.ToHTML([]byte(value), nil, nil)
	policy := bluemonday.UGCPolicy()
	safeHTML := policy.SanitizeBytes(html)
	return bytes.Equal(html, safeHTML), nil
}
