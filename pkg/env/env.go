// parkjunwoo.com/microstral/pkg/env/env.go
package env

import (
	"os"
	"strconv"
)

// GetEnv는 환경 변수 값을 string으로 반환합니다.
func GetEnv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

// GetEnvBool는 환경 변수 값을 bool로 변환하여 반환합니다.
func GetEnvBool(key string, def bool) bool {
	if val := os.Getenv(key); val != "" {
		valBool, err := strconv.ParseBool(val)
		if err != nil {
			return def
		}
		return valBool
	}
	return def
}

// GetEnvInt는 환경 변수 값을 int로 변환하여 반환합니다.
func GetEnvInt(key string, def int) int {
	if val := os.Getenv(key); val != "" {
		valInt, err := strconv.Atoi(val)
		if err != nil {
			return def
		}
		return valInt
	}
	return def
}

// GetEnvInt는 환경 변수 값을 int로 변환하여 반환합니다.
func GetEnvInt64(key string, def int64) int64 {
	if val := os.Getenv(key); val != "" {
		valInt, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return def
		}
		return valInt
	}
	return def
}

func GetEnvFloat64(key string, def float64) float64 {
	if val := os.Getenv(key); val != "" {
		valFloat, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return def
		}
		return valFloat
	}
	return def
}
