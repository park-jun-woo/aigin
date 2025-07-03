// https://parkjunwoo.com/microstral/pkg/mttp/client.go
package mttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Response http.Response

type Client struct {
	client *http.Client
}

func NewClient() *Client {
	// HTTP 클라이언트 생성
	return &Client{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) Request(method string, url string, endpoint string, body interface{}, headers map[string]string) (*Response, error) {
	// 요청 바디 생성
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// HTTP 요청 생성
	req, err := http.NewRequest(method, url+endpoint, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("fail to Create HTTP Request: %v", err)
	}

	// 헤더 적용
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fail to HTTP Request: %v", err)
	}

	// 응답 코드가 200이 아닌 경우 에러 처리
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed request to %s(code:%d, message:%s)", endpoint, resp.StatusCode, bodyBytes)
	}

	// 정상 응답 반환
	return (*Response)(resp), nil
}
