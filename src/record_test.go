package main

import "testing"

func TestRecordGenerateTextRecord(t *testing.T) {
	testCases := []struct {
		name   string
		domain string
		key    string
		want   string
		err    bool
	}{
		{
			// VALID RECORD
			name:   "example.com",
			domain: "example.com",
			key:    "key",
			want:   "_acme-challenge.example.com.            TXT \"key\"",
			err:    false,
		},
		{
			name:   "invalid domain",
			domain: "example",
			key:    "key",
			want:   "",
			err:    true,
		},
		{
			name:   "empty",
			domain: "",
			key:    "",
			want:   "",
			err:    true,
		},
		{
			name:   "empty domain",
			domain: "",
			key:    "someting",
			want:   "",
			err:    true,
		},
		{
			name:   "empty key",
			domain: "example.com",
			key:    "",
			want:   "",
			err:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Record{
				Domain: tc.domain,
				Key:    tc.key,
			}

			got, err := r.GenerateTextRecord()
			if got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}

			if tc.err && err == nil {
				t.Error("expected error, got nil")
			}

			if !tc.err && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}

}

func TestRecordValidate(t *testing.T) {
	testCases := []struct {
		name   string
		domain string
		key    string
		valid  bool
	}{
		{
			name:   "empty domain",
			domain: "",
			key:    "key",
		},
		{
			name:   "empty key",
			domain: "example.com",
			key:    "",
		},
		{
			name:   "invalid domain",
			domain: "example",
			key:    "key",
		},
		{
			name:   "valid",
			domain: "example.com",
			key:    "key",
			valid:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Record{
				Domain: tc.domain,
				Key:    tc.key,
			}

			err := r.Validate()
			if tc.valid && err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if !tc.valid && err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
