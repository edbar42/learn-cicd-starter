package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		input http.Header
		want  string
		err   error
	}{
		// Valid case: Correct "Authorization" header with "ApiKey"
		{
			input: http.Header{
				"Authorization": []string{"ApiKey 12345abcde"},
			},
			want: "12345abcde",
			err:  nil,
		},

		// Case with missing "Authorization" header
		{
			input: http.Header{},
			want:  "",
			err:   ErrNoAuthHeaderIncluded,
		},

		// Case with malformed "Authorization" header (incorrect prefix)
		{
			input: http.Header{
				"Authorization": []string{"Bearer 12345abcde"},
			},
			want: "",
			err:  errors.New("malformed authorization header"),
		},

		// Case with missing API key part in the "Authorization" header
		{
			input: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want: "",
			err:  errors.New("malformed authorization header"),
		},

		// Case with an empty "Authorization" value
		{
			input: http.Header{
				"Authorization": []string{""},
			},
			want: "",
			err:  errors.New("no authorization header included"),
		},
	}

	for _, tc := range tests {
		got, err := GetAPIKey(tc.input)
		if err != nil && err.Error() != tc.err.Error() {
			t.Fatalf("expected error: %v, got: %v", tc.err, err)
		}
		if got != tc.want {
			t.Fatalf("expected: %v, got: %v", tc.want, got)
		}
	}
}
