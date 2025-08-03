package image

import (
	"encoding/base64"
	"errors"
	"mime"
	"strings"
)

// DataURL 예시: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."

func ParseBase64Image(dataurl string) (ext string, data []byte, err error) {
	const prefix = "data:"
	if !strings.HasPrefix(dataurl, prefix) {
		return "", nil, errors.New("invalid dataurl")
	}
	// data:image/png;base64,xxxx
	metaSep := strings.Index(dataurl, ",")
	if metaSep < 0 {
		return "", nil, errors.New("invalid dataurl")
	}
	metadata := dataurl[len(prefix):metaSep]
	payload := dataurl[metaSep+1:]

	// ex: metadata = "image/png;base64"
	parts := strings.Split(metadata, ";")
	if len(parts) != 2 || parts[1] != "base64" {
		return "", nil, errors.New("invalid dataurl (no base64)")
	}

	mimeType := parts[0]
	exts, err := mime.ExtensionsByType(mimeType)
	if err != nil || len(exts) == 0 {
		ext = ".png" // fallback
	} else {
		ext = exts[0]
	}

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", nil, err
	}

	return ext, decoded, nil
}
