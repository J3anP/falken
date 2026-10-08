package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

func CrtShSubdomains(ctx context.Context, domain string, timeoutMs int) ([]string, error) {
	queryURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape("%."+domain))

	client := &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh respondió %d", resp.StatusCode)
	}

	var entries []crtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("no se pudo parsear la respuesta de crt.sh: %w", err)
	}

	seen := make(map[string]bool)
	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			sub := strings.ToLower(strings.TrimSpace(line))
			sub = strings.TrimPrefix(sub, "*.")
			if sub == "" || sub == strings.ToLower(domain) {
				continue
			}
			seen[sub] = true
		}
	}

	result := make([]string, 0, len(seen))
	for sub := range seen {
		result = append(result, sub)
	}
	sort.Strings(result)
	return result, nil
}