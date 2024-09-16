package auth

import (
	"net/http"
	"testing"
	"errors"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantAPIKey string
		wantErr    error
	}{
		{
			name:       "No Authorization Header",
			headers:    http.Header{},
			wantAPIKey: "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			wantAPIKey: "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name: "Invalid Authorization Type",
			headers: http.Header{
				"Authorization": []string{"Basic abc123"},
			},
			wantAPIKey: "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name: "Valid Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			wantAPIKey: "abc123",
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)
			if apiKey != tt.wantAPIKey {
				t.Errorf("got API key %q, want %q", apiKey, tt.wantAPIKey)
			}
			if err != nil && err.Error() != tt.wantErr.Error() {
				ta.Errorf("got error %q, want %q", err, tt.wantErr)
			}
		})
	}
}

