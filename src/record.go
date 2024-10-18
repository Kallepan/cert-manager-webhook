/*
This file provides the Record struct and its methods.
The struct can be used to represent a DNS record that needs to be added to a zone file and contains a domain and a key.
The GenerateTextRecord method generates a string representation of the record in the format required for a zone file.
The Validate method checks if the domain and key are not empty and if the domain has a valid format.
*/
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
)

const VALID_DOMAIN_REGEX = `^([_a-z0-9]+([-a-z0-9]+)*\.)+[a-z]{2,}\.?$`

// Precompiled regex for domain validation
var domainRegex = regexp.MustCompile(VALID_DOMAIN_REGEX)

type Record struct {
	Domain string
	Key    string
}

// NewRecord creates a new Record with the provided domain and key.
func NewRecord(domain, key string) *Record {
	// Remove the root domain from the domain if defined
	domain = removeRootDomain(domain, os.Getenv("ROOT_DOMAIN"))
	domain = removeTrailingDot(domain)

	return &Record{
		Domain: domain,
		Key:    key,
	}
}

func removeRootDomain(domain string, rootDomain string) string {
	if rootDomain == "" {
		return domain
	}

	re, err := regexp.Compile(fmt.Sprintf(`%s\.?$`, rootDomain))
	if err != nil {
		slog.Info("Error compiling regex", "rootDomain", rootDomain, "error", err)
		return domain
	}

	return re.ReplaceAllString(domain, "")
}

func removeTrailingDot(domain string) string {
	if len(domain) == 0 {
		return domain
	}
	if domain[len(domain)-1] == '.' {
		return domain[:len(domain)-1]
	}

	return domain
}

func (r *Record) GenerateTextRecord() (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s            TXT \"%s\"", r.Domain, r.Key), nil
}

func (r *Record) Validate() error {
	// Check if the domain is empty
	if r.Domain == "" {
		return errors.New("domain is required")
	}

	// Check if the key is empty
	if r.Key == "" {
		return errors.New("key is required")
	}

	// Validate the domain against the regex
	if !domainRegex.MatchString(r.Domain) {
		return errors.New("invalid domain format")
	}

	return nil
}
