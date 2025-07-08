// parkjunwoo.com/microstral/pkg/secure/util.go
package secure

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// calcSecretHash calculates the AWS Cognito SecretHash.
func CalcSecretHash(clientID, clientSecret, username string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func BasicAuth(clientID, clientSecret string) string {
	auth := clientID + ":" + clientSecret
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
