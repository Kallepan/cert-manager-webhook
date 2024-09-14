package main

import (
	"errors"
	"reflect"
	"testing"
)

func TestAddTxtRecord(t *testing.T) {
	testCases := []struct {
		name      string
		content   string
		recordStr string
		want      string
		err       error
	}{
		{
			name:      "empty content",
			content:   "",
			recordStr: "_acme-challenge.example.com TXT \"somevalue\"",
			want:      "",
			err:       nil,
		},
		{
			name:      "single record",
			content:   "; ACME-BOT\nsome content\n; ACME-BOT-END",
			recordStr: "_acme-challenge.example.com TXT \"somevalue\"",
			want:      "; ACME-BOT\nsome content\n_acme-challenge.example.com TXT \"somevalue\"\n; ACME-BOT-END",
			err:       nil,
		},
		{
			name:      "no opening comment",
			content:   "some content\n; ACME-BOT-END",
			recordStr: "_acme-challenge.example.com TXT \"somevalue\"",
			want:      "some content\n_acme-challenge.example.com TXT \"somevalue\"\n; ACME-BOT-END",
			err:       nil,
		},
		{
			name:      "surrounding text",
			content:   "text-before; ACME-BOT\nsome content\n; ACME-BOT-ENDtext-text-after",
			recordStr: "_acme-challenge.example.com TXT \"somevalue\"",
			want:      "text-before; ACME-BOT\nsome content\n_acme-challenge.example.com TXT \"somevalue\"\n; ACME-BOT-ENDtext-text-after",
			err:       nil,
		},
		{
			name:      "trailing newline",
			content:   "; ACME-BOT\nsome content\n; ACME-BOT-END\n",
			recordStr: "_acme-challenge.example.com TXT \"somevalue\"",
			want:      "; ACME-BOT\nsome content\n_acme-challenge.example.com TXT \"somevalue\"\n; ACME-BOT-END\n",
			err:       nil,
		},
		{
			name:      "no acme bot content",
			content:   "no acme bot content here",
			recordStr: "_acme-challenge.example.com TXT \"somevalue\"",
			want:      "no acme bot content here",
			err:       nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := addTxtRecord(tc.content, tc.recordStr)
			if !reflect.DeepEqual(actual, tc.want) {
				t.Errorf("expected %q, got %q", tc.want, actual)
			}

			if tc.err == nil && err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if tc.err != nil {
				if err == nil {
					t.Error("expected error, got nil")
				}

				if err.Error() != tc.err.Error() {
					t.Errorf("expected error %q, got %q", tc.err, err)
				}
			}
		})
	}
}

func TestRemoveTxtRecord(t *testing.T) {
	testCases := []struct {
		name      string
		content   string
		recordStr string
		want      string
		err       error
	}{
		{
			name:      "empty content",
			content:   "",
			recordStr: "_acme-challenge.example.com TXT \"somevalue\"",
			want:      "",
		},
		{
			name:      "single record with trailing newline",
			content:   "_acme-challenge.example.com TXT \"somevalue\"\notherrecord",
			recordStr: "_acme-challenge.example.com TXT \"somevalue\"",
			want:      "otherrecord",
		},
		{
			name:      "multiple records",
			content:   "_acme-challenge.example.com TXT \"somevalue\"\n_acme-challenge.example.com TXT \"anothervalue\"\n",
			recordStr: "_acme-challenge.example.com TXT \"somevalue\"",
			want:      "_acme-challenge.example.com TXT \"anothervalue\"\n",
		},
		{
			name:    "no record",
			content: "someotherrecord",
			want:    "someotherrecord",
		},
		{
			name:      "multiple records different domains",
			content:   "_acme-challenge.example.com TXT \"somevalue\"\n_acme-challenge.test.com TXT \"anothervalue\"\n",
			recordStr: "_acme-challenge.test.com TXT \"anothervalue\"",
			want:      "_acme-challenge.example.com TXT \"somevalue\"\n",
		},
		{
			name:      "wrong recordStr",
			content:   "_acme-challenge.example.com TXT \"somevalue\"\n_acme-challenge.example.com TXT \"anothervalue\"\n",
			recordStr: "example.com",
			want:      "_acme-challenge.example.com TXT \"somevalue\"\n_acme-challenge.example.com TXT \"anothervalue\"\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := removeTxtRecord(tc.content, tc.recordStr)
			if !reflect.DeepEqual(actual, tc.want) {
				t.Errorf("expected %q, got %q", tc.want, actual)
			}

			if tc.err == nil && err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if tc.err != nil {
				if err == nil {
					t.Error("expected error, got nil")
				}

				if err.Error() != tc.err.Error() {
					t.Errorf("expected error %q, got %q", tc.err, err)
				}
			}
		})
	}
}

func TestExtractAcmeBotContent(t *testing.T) {
	testCases := []struct {
		name    string
		content string
		want    string
		err     error
	}{
		{
			name:    "valid content with text",
			content: "; ACME-BOT\nsome content\n; ACME-BOT-END",
			want:    "some content\n",
			err:     nil,
		},
		{
			name:    "valid content with another text",
			content: "; ACME-BOT\nanother content\n; ACME-BOT-END",
			want:    "another content\n",
			err:     nil,
		},
		{
			name:    "valid content with multiple texts",
			content: "; ACME-BOT\nanother content\nblah\nblahhhshhh\n; ACME-BOT-END",
			want:    "another content\nblah\nblahhhshhh\n",
			err:     nil,
		},
		{
			name:    "empty content",
			content: "",
			want:    "",
			err:     errors.New("ACME-BOT comments not found"),
		},
		{
			name:    "single comment",
			content: "no acme bot content here",
			want:    "",
			err:     errors.New("ACME-BOT comments not found"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &gitSolver{}
			got, err := h.extractAcmeBotContent(tc.content)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("expected %q, got %q", tc.want, got)
			}

			if tc.err == nil && err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if tc.err != nil {
				if err == nil {
					t.Error("expected error, got nil")
				}

				if err.Error() != tc.err.Error() {
					t.Errorf("expected error %q, got %q", tc.err, err)
				}
			}
		})
	}
}

func TestExtractTxtRecords(t *testing.T) {
	testCases := []struct {
		name    string
		content string
		want    map[string]string
		err     error
	}{
		{
			name:    "valid single record",
			content: "_acme-challenge.example.com TXT \"somevalue\"\n",
			want:    map[string]string{"example.com": "somevalue"},
			err:     nil,
		},
		{
			name:    "valid multiple records",
			content: "_acme-challenge.example.com TXT \"somevalue\"\n_acme-challenge.test.com TXT \"anothervalue\"\n",
			want:    map[string]string{"example.com": "somevalue", "test.com": "anothervalue"},
			err:     nil,
		},
		{
			name:    "no records",
			content: "no txt records here",
			want:    nil,
			err:     errors.New("no TXT records found"),
		},
		{
			name:    "invalid format",
			content: "_acme-challenge.example.com TXT somevalue\n",
			want:    nil,
			err:     errors.New("no TXT records found"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &gitSolver{}
			got, err := h.extractTxtRecords(tc.content)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("expected %v, got %v", tc.want, got)
			}

			if tc.err == nil && err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if tc.err != nil {
				if err == nil {
					t.Error("expected error, got nil")
				}

				if err.Error() != tc.err.Error() {
					t.Errorf("expected error %q, got %q", tc.err, err)
				}
			}
		})
	}
}
