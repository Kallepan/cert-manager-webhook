package main

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
)

func TestGitlabIntegration(t *testing.T) {
	solver := New()
	if err := solver.Initialize(nil, nil); err != nil {
		t.Fatal(err)
	}

	// Test Adding a new record
	challenge := &acme.ChallengeRequest{
		ResolvedFQDN: "test.example.com",
		Key:          "wow-so-secret",
	}
	if err := solver.Present(challenge); err != nil {
		t.Fatal(err)
	}

	if err := solver.Present(challenge); err != nil && err != ErrTextRecordAlreadyExists {
		t.Fatal(err)
	}

	// Test Removing the record
	if err := solver.CleanUp(challenge); err != nil {
		t.Fatal(err)
	}

	if err := solver.CleanUp(challenge); err != nil && err != ErrTextRecordDoesNotExist {
		t.Fatal(err)
	}
}

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
			content:   "; TEST-ACME-BOT\nsome content\n; TEST-ACME-BOT-END",
			recordStr: "_acme-challenge.example.com TXT \"somevalue\"",
			want:      "; TEST-ACME-BOT\nsome content\n_acme-challenge.example.com TXT \"somevalue\"\n; TEST-ACME-BOT-END",
			err:       nil,
		},
		{
			name:      "no opening comment",
			content:   "some content\n; ACME-BOT-END",
			recordStr: "_acme-challenge.example.com TXT \"somevalue\"",
			want:      "some content\n; ACME-BOT-END",
			err:       nil,
		},
		{
			name:      "surrounding text",
			content:   "text-before; TEST-ACME-BOT\nsome content\n; TEST-ACME-BOT-ENDtext-text-after",
			recordStr: "_acme-challenge.example.com TXT \"somevalue\"",
			want:      "text-before; TEST-ACME-BOT\nsome content\n_acme-challenge.example.com TXT \"somevalue\"\n; TEST-ACME-BOT-ENDtext-text-after",
			err:       nil,
		},
		{
			name:      "trailing newline",
			content:   "; TEST-ACME-BOT\nsome content\n; TEST-ACME-BOT-END\n",
			recordStr: "_acme-challenge.example.com TXT \"somevalue\"",
			want:      "; TEST-ACME-BOT\nsome content\n_acme-challenge.example.com TXT \"somevalue\"\n; TEST-ACME-BOT-END\n",
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
			actual, err := addTxtRecord(tc.content, tc.recordStr, "TEST")
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
			content: "; TEST-ACME-BOT\nsome content\n; TEST-ACME-BOT-END",
			want:    "some content\n",
			err:     nil,
		},
		{
			name:    "valid content with another text",
			content: "; TEST-ACME-BOT\nanother content\n; TEST-ACME-BOT-END",
			want:    "another content\n",
			err:     nil,
		},
		{
			name:    "valid content with multiple texts",
			content: "; TEST-ACME-BOT\nanother content\nblah\nblahhhshhh\n; TEST-ACME-BOT-END",
			want:    "another content\nblah\nblahhhshhh\n",
			err:     nil,
		},
		{
			name:    "empty content",
			content: "",
			want:    "",
			err:     ErrACMEBotContentNotFound,
		},
		{
			name:    "single comment",
			content: "no acme bot content here",
			want:    "",
			err:     ErrACMEBotContentNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &gitSolver{
				// Set the prefix to TEST to match the test cases
				gitBotCommentPrefix: "TEST",
			}
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
		name       string
		content    string
		want       map[string]string
		err        error
		rootDomain string
	}{
		{
			name:       "with root domain",
			content:    "_acme-challenge.svc TXT \"somevalue\"\n",
			want:       map[string]string{"_acme-challenge.svc.example.com.": "somevalue"},
			err:        nil,
			rootDomain: "example.com",
		},
		{
			name:       "with root domain. multiple records",
			content:    "_acme-challenge.svc TXT \"somevalue\"\n_acme-challenge.svc2 TXT \"anothervalue\"\n",
			want:       map[string]string{"_acme-challenge.svc.example.com.": "somevalue", "_acme-challenge.svc2.example.com.": "anothervalue"},
			err:        nil,
			rootDomain: "example.com",
		},
		{
			name:    "valid single record",
			content: "_acme-challenge.example.com TXT \"somevalue\"\n",
			want:    map[string]string{"_acme-challenge.example.com.": "somevalue"},
			err:     nil,
		},
		{
			name:    "valid multiple records",
			content: "_acme-challenge.example.com TXT \"somevalue\"\n_acme-challenge.test.com TXT \"anothervalue\"\n",
			want:    map[string]string{"_acme-challenge.example.com.": "somevalue", "_acme-challenge.test.com.": "anothervalue"},
			err:     nil,
		},
		{
			name:    "no records",
			content: "no txt records here",
			want:    map[string]string{},
			err:     ErrTextRecordsDoNotExist,
		},
		{
			name:    "invalid format",
			content: "_acme-challenge.example.com TXT somevalue\n",
			want:    map[string]string{},
			err:     ErrTextRecordsDoNotExist,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.rootDomain != "" {
				os.Setenv("ROOT_DOMAIN", tc.rootDomain)
				defer os.Unsetenv("ROOT_DOMAIN")
			}

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

func TestIncreaseSerialNumber(t *testing.T) {
	currentDate := time.Now().Format("20060102")
	testCases := []struct {
		name    string
		content string
		want    string
		err     error
	}{
		{
			name:    "No space after and before serial number",
			content: fmt.Sprintf("%s01;serial number", currentDate),
			want:    fmt.Sprintf("%s02 ; serial number", currentDate),
			err:     nil,
		},
		{
			name:    "Space after serial number",
			content: fmt.Sprintf("%s01; serial number", currentDate),
			want:    fmt.Sprintf("%s02 ; serial number", currentDate),
			err:     nil,
		},
		{
			name:    "Space before serial number",
			content: fmt.Sprintf("%s01 ;serial number", currentDate),
			want:    fmt.Sprintf("%s02 ; serial number", currentDate),
			err:     nil,
		},
		{
			name:    "Space after and before serial number",
			content: fmt.Sprintf("%s01 ; serial number", currentDate),
			want:    fmt.Sprintf("%s02 ; serial number", currentDate),
			err:     nil,
		},
		{
			name:    "No serial number",
			content: "no serial number here",
			want:    "",
			err:     ErrSerialNumberNotFound,
		},
		{
			name: "Empty content",
			want: "",
			err:  ErrSerialNumberNotFound,
		},
		{
			name:    "Serial Number with old date 01",
			content: fmt.Sprintf("%s01 ; serial number", "20211001"),
			want:    fmt.Sprintf("%s01 ; serial number", currentDate),
		},
		{
			name:    "Serial Number with old date 02",
			content: fmt.Sprintf("%s02 ; serial number", "20211001"),
			want:    fmt.Sprintf("%s01 ; serial number", currentDate),
		},
		{
			name:    "Serial Number ends with 99",
			content: fmt.Sprintf("%s99 ; serial number", currentDate),
			want:    fmt.Sprintf("%s00 ; serial number", currentDate),
		},
		{
			name: "Large content",
			content: `; SOA Record
				@ IN SOA ns1.example.com. hostmaster.example.com. (
				2021100101 ; serial number
				3600 ; refresh`,
			want: fmt.Sprintf(`; SOA Record
				@ IN SOA ns1.example.com. hostmaster.example.com. (
				%s01 ; serial number
				3600 ; refresh`, currentDate),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &gitSolver{}
			got, err := h.increaseSerialNumber(tc.content)
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
