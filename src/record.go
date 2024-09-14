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
	"regexp"
)

const VALID_DOMAIN_REGEX = `^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$`

// Precompiled regex for domain validation
var domainRegex = regexp.MustCompile(VALID_DOMAIN_REGEX)

type Record struct {
	Domain string
	Key    string
}

// NewRecord creates a new Record with the provided domain and key.
func NewRecord(domain, key string) *Record {
	return &Record{
		Domain: domain,
		Key:    key,
	}
}

func (r *Record) GenerateTextRecord() (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf("_acme-challenge.%s.            TXT \"%s\"", r.Domain, r.Key), nil
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
