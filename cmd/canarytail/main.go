package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"
)

type Message struct {
	Domain      string         `json:"DOMAIN"`
	PubKey      string         `json:"PUBKEY"`
	NewKey      string         `json:"NEWKEY"`
	PanicKey    string         `json:"PANICKEY"`
	Version     string         `json:"VERSION"`
	ReleaseDate time.Time      `json:"RELEASE"`
	ExpireDate  time.Time      `json:"EXPIRES"`
	Freshness   string         `json:"FRESHNESS"`
	Codes       map[string]int `json:"CODES"`
}

func printUsage() {
	fmt.Println("Usage:\n\tcanarytail https://www.example.com/canary.txt")
}

func failOnErr(err error, msg string) {
	if err != nil {
		fmt.Printf("error: %s\n", msg)
		os.Exit(0)
	}
}

func main() {
	// read args
	args := os.Args[1:]
	if len(args) != 1 {
		printUsage()
		os.Exit(0)
	}
	addr := args[0]

	// parse and validate url
	url, err := url.Parse(addr)
	failOnErr(err, "failed to parse url")

	// do the http request
	client := http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(addr)
	failOnErr(err, "failed to make HTTP request")

	canary, err := ioutil.ReadAll(resp.Body)
	failOnErr(err, "failed to read response")
	resp.Body.Close()

	// parse json message
	msg, err := parseMessage(canary)
	failOnErr(err, errCanaryParse.Error())

	// validate the canary and print alerts if any
	alerts := validateMessage(msg, url.Hostname())
	if len(alerts) == 0 {
		fmt.Println("Warrant canary is valid!")
	}

	for _, alert := range alerts {
		fmt.Printf("ALERT: %s\n", alert)
	}
}
