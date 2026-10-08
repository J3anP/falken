package scanner

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"strings"
	"time"
)

func FaviconHash(ctx context.Context, target string, useHTTPS bool, timeoutMs int) (string, error) {
	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/favicon.ico", scheme, target)

	client := &http.Client{
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("favicon.ico no disponible (status %d)", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if len(body) == 0 {
		return "", fmt.Errorf("favicon.ico vacío")
	}

	encoded := base64.StdEncoding.EncodeToString(body)
	encoded = insertLineBreaks(encoded, 76)

	hash := murmur3Hash32([]byte(encoded), 0)
	return fmt.Sprintf("%d", hash), nil
}

func insertLineBreaks(s string, every int) string {
	var sb strings.Builder
	for i := 0; i < len(s); i += every {
		end := i + every
		if end > len(s) {
			end = len(s)
		}
		sb.WriteString(s[i:end])
		sb.WriteByte('\n')
	}
	return sb.String()
}

func murmur3Hash32(data []byte, seed uint32) int32 {
	const c1 = 0xcc9e2d51
	const c2 = 0x1b873593

	h1 := seed
	nblocks := len(data) / 4

	for i := 0; i < nblocks; i++ {
		k1 := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2

		h1 ^= k1
		h1 = bits.RotateLeft32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}

	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return int32(h1)
}