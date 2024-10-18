package main

import (
	"os"
	"testing"
)

func TestRemoveRootDomain(t *testing.T) {
	testCases := []struct {
		name       string
		domain     string
		rootDomain string
		want       string
	}{
		{
			name:       "remove root domain",
			domain:     "sub.example.com.",
			rootDomain: "example.com",
			want:       "sub.",
		},
		{
			name:       "remove root domain",
			domain:     "sub.example.com",
			rootDomain: "example.com",
			want:       "sub.",
		},
		{
			name:       "no root domain",
			domain:     "sub.example.com",
			rootDomain: "",
			want:       "sub.example.com",
		},
		{
			name:       "root domain not at end",
			domain:     "example.com.sub",
			rootDomain: "example.com",
			want:       "example.com.sub",
		},
		{
			name:       "exact match",
			domain:     "example.com",
			rootDomain: "example.com",
			want:       "",
		},
		{
			name:       "root domain with trailing dot",
			domain:     "sub.example.com.",
			rootDomain: "example.com.",
			want:       "sub.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := removeRootDomain(tc.domain, tc.rootDomain)
			if got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestRemoveTrailingDot(t *testing.T) {
	testCases := []struct {
		name   string
		domain string
		want   string
	}{
		{
			name:   "domain with trailing dot",
			domain: "example.com.",
			want:   "example.com",
		},
		{
			name:   "domain without trailing dot",
			domain: "example.com",
			want:   "example.com",
		},
		{
			name:   "empty domain",
			domain: "",
			want:   "",
		},
		{
			name:   "single dot",
			domain: ".",
			want:   "",
		},
		{
			name:   "multiple trailing dots",
			domain: "example.com..",
			want:   "example.com.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := removeTrailingDot(tc.domain)
			if got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestGenerateTextRecord(t *testing.T) {
	testCases := []struct {
		name       string
		domain     string
		key        string
		want       string
		err        bool
		rootDomain string
	}{
		{
			// VALID RECORD
			name:   "example.com",
			domain: "_acme-challenge.example.com.",
			key:    "key",
			want:   "_acme-challenge.example.com            TXT \"key\"",
			err:    false,
		},
		{
			name:       "svc.example.com",
			domain:     "_acme-challenge.svc",
			key:        "key",
			want:       "_acme-challenge.svc            TXT \"key\"",
			rootDomain: "example.com",
		},
		{
			name:       "svc.example.com.",
			domain:     "_acme-challenge.svc.example.com.",
			key:        "key",
			want:       "_acme-challenge.svc            TXT \"key\"",
			rootDomain: "example.com",
		},
		{
			name:       "svc.example.com.",
			domain:     "_acme-challenge.svc.example.com",
			key:        "key",
			want:       "_acme-challenge.svc            TXT \"key\"",
			rootDomain: "example.com",
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
		if tc.rootDomain != "" {
			os.Setenv("ROOT_DOMAIN", tc.rootDomain)
			defer os.Unsetenv("ROOT_DOMAIN")
		}

		r := NewRecord(tc.domain, tc.key)
		t.Run(tc.name, func(t *testing.T) {
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
			domain: "_acme-challenge.example.com.",
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
