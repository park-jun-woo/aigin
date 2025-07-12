// internal/cloudfront/signedcookie.go
package cloudfront

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"parkjunwoo.com/microstral/pkg/env"
)

type CloudFrontModel struct {
	CloudfrontID     string
	CloudfrontSecret string
}

type CloudFrontPolicy struct {
	Statement []struct {
		Resource  string                 `json:"Resource"`
		Condition map[string]interface{} `json:"Condition"`
	} `json:"Statement"`
}

func NewCloudFrontModel(awsCfg aws.Config) *CloudFrontModel {
	// 환경 변수에서 설정 값 가져오기
	cloudfrontSecretName := env.GetEnv("CLOUDFRONT_SECRET", "")
	// AWS Secrets Manager 클라이언트 생성
	smClient := secretsmanager.NewFromConfig(awsCfg)
	// CloudFront 시크릿 가져오기
	cloudfrontSecret, err := smClient.GetSecretValue(context.TODO(), &secretsmanager.GetSecretValueInput{
		SecretId: &cloudfrontSecretName,
	})
	if err != nil {
		log.Fatalf("unable to retrieve secret %s", cloudfrontSecretName)
		return nil
	}
	// CognitoModel 인스턴스 생성
	return &CloudFrontModel{
		CloudfrontID:     env.GetEnv("CLOUDFRONT_ID", ""),
		CloudfrontSecret: *cloudfrontSecret.SecretString,
	}
}

func (m *CloudFrontModel) CreateSignedCookies(resourceURL string, expireAt time.Time) (map[string]string, error) {
	// 1. 정책(Policy) 생성
	policyStruct := CloudFrontPolicy{
		Statement: []struct {
			Resource  string                 `json:"Resource"`
			Condition map[string]interface{} `json:"Condition"`
		}{
			{
				Resource: resourceURL,
				Condition: map[string]interface{}{
					"DateLessThan": map[string]int64{
						"AWS:EpochTime": expireAt.Unix(),
					},
				},
			},
		},
	}
	policyJson, err := json.Marshal(policyStruct)
	if err != nil {
		return nil, err
	}
	policyB64 := base64.RawURLEncoding.EncodeToString(policyJson)

	// 2. 프라이빗 키 파싱
	privKey, err := parseRSAPrivateKeyFromPEM(m.CloudfrontSecret)
	if err != nil {
		return nil, err
	}

	// 3. 정책에 서명 (RSA SHA1)
	signature, err := signPolicyRSA_SHA1(policyB64, privKey)
	if err != nil {
		return nil, err
	}

	// 4. 쿠키 세트 반환
	return map[string]string{
		"CloudFront-Policy":      policyB64,
		"CloudFront-Signature":   signature,
		"CloudFront-Key-Pair-Id": m.CloudfrontID,
	}, nil
}

func signPolicyRSA_SHA1(policyB64 string, privateKey *rsa.PrivateKey) (string, error) {
	hashed := crypto.SHA1.New()
	hashed.Write([]byte(policyB64))
	digest := hashed.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, digest)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func parseRSAPrivateKeyFromPEM(keyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		privInterface, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, err
		}
		rsaPriv, ok := privInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not RSA private key")
		}
		return rsaPriv, nil
	}
	return priv, nil
}
