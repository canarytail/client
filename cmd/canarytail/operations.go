package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func opValidateCanary(addr string) (string, error) {
	// parse and validate url
	url, err := url.Parse(addr)
	if err != nil {
		return "", &ConsoleError{Message: "failed to parse url", Err: err}
	}

	// do the http request
	client := http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(addr)
	if err != nil {
		return "", &ConsoleError{Message: "failed to make HTTP request", Err: err}
	}

	canary, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", &ConsoleError{Message: "failed to read HTTP response", Err: err}
	}
	resp.Body.Close()

	// parse json message
	msg, err := parseMessage(canary)
	if err != nil {
		return "", err
	}

	// validate the canary and print alerts if any
	alerts := validateMessage(msg, url.Hostname())
	if len(alerts) == 0 {
		return "Warrant canary is valid!", nil
	}

	alertsStr := ""
	for _, alert := range alerts {
		alertsStr += fmt.Sprintf("ALERT: %s\n", alert)
	}

	return alertsStr, nil
}

func opNewCanaryInteractive() (string, error) {
	prompt := NewStdinPrompt()

	domain, err := prompt.Input("Enter domain name")
	if err != nil {
		return "", err
	}
	if domain == "" {
		return "", &ConsoleError{Message: "domain name cannot be empty"}
	}

	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	if !strings.HasPrefix(domain, "www.") {
		domain = "www." + domain
	}

	version, err := prompt.Input("Enter canary version")
	if err != nil {
		return "", err
	}

	validDaysStr, err := prompt.Input("Enter validity period (number of days)")
	if err != nil {
		return "", err
	}
	validDays, err := strconv.Atoi(validDaysStr)
	if err != nil {
		return "", &ConsoleError{Message: "bad validity period", Err: err}
	}

	// build the codes
	codes := make([]string, 0)
	war, err := prompt.InputWithOptions("Have you received warrants ?", []string{"y", "N"}, "N")
	if err != nil {
		return "", err
	}
	if war == "N" {
		codes = append(codes, "WAR")
	}

	gag, err := prompt.InputWithOptions("Have you received gag orders ?", []string{"y", "N"}, "N")
	if err != nil {
		return "", err
	}
	if gag == "N" {
		codes = append(codes, "GAG")
	}

	subp, err := prompt.InputWithOptions("Have you received subpoenas ?", []string{"y", "N"}, "N")
	if err != nil {
		return "", err
	}
	if subp == "N" {
		codes = append(codes, "SUBP")
	}

	trap, err := prompt.InputWithOptions("Have you received trap or trace orders ?", []string{"y", "N"}, "N")
	if err != nil {
		return "", err
	}
	if trap == "N" {
		codes = append(codes, "TRAP")
	}

	cease, err := prompt.InputWithOptions("Have you received any court orders to cease operations ?", []string{"y", "N"}, "N")
	if err != nil {
		return "", err
	}
	if cease == "N" {
		codes = append(codes, "CEASE")
	}

	duress, err := prompt.InputWithOptions("Have you been coerced, blackmailed, or operated under duress ?", []string{"y", "N"}, "N")
	if err != nil {
		return "", err
	}
	if duress == "N" {
		codes = append(codes, "DURESS")
	}

	raid, err := prompt.InputWithOptions("Have you had raids with HIGH confidence nothing containing useful data was seized ?", []string{"y", "N"}, "N")
	if err != nil {
		return "", err
	}
	if raid == "N" {
		codes = append(codes, "RAID")
	}

	seize, err := prompt.InputWithOptions("Have you had raids with LOW confidence nothing containing useful data was seized ?", []string{"y", "N"}, "N")
	if err != nil {
		return "", err
	}
	if seize == "N" {
		codes = append(codes, "SEIZE")
	}

	xcred, err := prompt.InputWithOptions("Have any credentials been compormised ?", []string{"y", "N"}, "N")
	if err != nil {
		return "", err
	}
	if xcred == "N" {
		codes = append(codes, "XCRED")
	}

	xopers, err := prompt.InputWithOptions("Have your operational integrity been compormised ?", []string{"y", "N"}, "N")
	if err != nil {
		return "", err
	}
	if xopers == "N" {
		codes = append(codes, "XOPERS")
	}

	releaseDate := time.Now()
	expirationDate := releaseDate.Add(time.Duration(validDays) * 24 * time.Hour)
	msg := Message{
		Domain:      domain,
		PubKey:      "",
		NewPubKey:   "",
		PanicKey:    "",
		NewPanicKey: "",
		Version:     version,
		Release:     releaseDate.Format(timeLayout),
		Expire:      expirationDate.Format(timeLayout),
		Freshness:   "",
		Codes:       codes,
	}
	prettyJson, err := json.MarshalIndent(msg, "", "\t")
	if err != nil {
		return "", &ConsoleError{Message: "unexpected program error", Err: err}
	}

	return fmt.Sprintf(
		"%s\n%s\n%s\n\n%s\n",
		beginMessage,
		string(prettyJson),
		beginSignature,
		endMessage), nil
}
