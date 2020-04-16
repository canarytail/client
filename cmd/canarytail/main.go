package main

import (
	"fmt"
	"os"
	"time"
)

type Message struct {
	Domain      string   `json:"DOMAIN"`
	PubKey      string   `json:"PUBKEY"`
	NewPubKey   string   `json:"NEWPUBKEY"`
	PanicKey    string   `json:"PANICKEY"`
	NewPanicKey string   `json:"NEWPANICKEY"`
	Version     string   `json:"VERSION"`
	Release     string   `json:"RELEASE"` // see timeLayout
	Expire      string   `json:"EXPIRY"`
	Freshness   string   `json:"FRESHNESS"`
	Codes       []string `json:"CODES"`

	ReleaseDate time.Time `json:"-"`
	ExpireDate  time.Time `json:"-"`
}

func printUsage() {
	fmt.Println("Usage:\n\tcanarytail https://www.example.com/canary.txt")
}

func failOnErr(err error) {
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
		os.Exit(0)
	}
}

type ConsoleError struct {
	Message string
	Err     error
}

func (e *ConsoleError) Error() string {
	return e.Message
}

func (e *ConsoleError) Debug() string {
	return fmt.Sprintf("%s: %s", e.Message, e.Err)
}

func main() {
	// read args
	args := os.Args[1:]
	if len(args) != 1 {
		printUsage()
		os.Exit(0)
	}

	switch args[0] {
	case "new":
		res, err := opNewCanaryInteractive()
		failOnErr(err)
		fmt.Println(res)
	default:
		res, err := opValidateCanary(args[0])
		failOnErr(err)
		fmt.Println(res)
	}

}
