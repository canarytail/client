package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	beginMessage   = []byte("-----BEGIN CANARY SIGNED MESSAGE-----")
	beginSignature = []byte("-----BEGIN SIGNATURE-----")

	errCanaryParse = errors.New("failed to parse canary message")

	alertInvalidDomain      = "Invalid canary domain"
	alertInvalidReleaseDate = "Invalid canary release date (in future)"
	alertInvalidExpireDate  = "Invalid canary expire date (expired)"
	alertWAR                = "Warrants received"
	alertGAG                = "Gag orders received"
	alertSUBP               = "Subpoenas received"
	alertTRAP               = "Trap and trace orders received"
	alertCEASE              = "Court order to cease operations received"
	alertDURESS             = "Coercion, blackmail, or otherwise operating under duress"
	alertRAID               = "Raids with high confidence nothing containing useful data was seized"
	alertSEIZE              = "Raids with low confidence nothing containing useful data was seized"
	alertXCRED              = "Compromised credentials"
	alertXOPERS             = "Compromised operations"
	alertSEPU               = "No Seppuku pledge"

	alertsMap = map[string]string{
		"WAR":    alertWAR,
		"GAG":    alertGAG,
		"SUBP":   alertSUBP,
		"TRAP":   alertTRAP,
		"CEASE":  alertCEASE,
		"DURESS": alertDURESS,
		"RAID":   alertRAID,
		"SEIZE":  alertSEIZE,
		"XCRED":  alertXCRED,
		"XOPERS": alertXOPERS,
		"SEPU":   alertSEPU,
	}
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

func parseMessage(canary []byte) (*Message, error) {

	// locate message bytes
	i := bytes.Index(canary, beginMessage)
	if i < 0 {
		return nil, errCanaryParse
	}

	start := i + len(beginMessage)
	end := len(canary)

	i = bytes.Index(canary, beginSignature)
	if i > 0 {
		end = i
	}
	canary = canary[start:end]

	// unmarshall message
	var msg Message
	if err := json.Unmarshal(canary, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

func validateMessage(msg *Message, host string) (alerts []string) {
	if !strings.HasPrefix(host, "www") {
		host = "www." + host
	}

	// 1) validate domain
	if msg.Domain != host {
		alerts = append(alerts, alertInvalidDomain)
		return
	}

	// 2) validate release date
	now := time.Now()
	if msg.ReleaseDate.After(now) {
		alerts = append(alerts, alertInvalidReleaseDate)
		return
	}

	// 3) validate expire date
	if msg.ExpireDate.Before(now) {
		alerts = append(alerts, alertInvalidExpireDate)
		return
	}

	// 4) collect the flags
	for code, val := range msg.Codes {
		if (val == 0 && code != "SEPU") || (val == 1 && code == "SEPU") {
			continue
		}

		if alert, ok := alertsMap[code]; ok {
			alerts = append(alerts, alert)
		}
	}

	return
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
