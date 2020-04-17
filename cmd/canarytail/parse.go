package main

import (
	"bytes"
	"encoding/json"
	"time"
)

var (
	timeLayout     string = "2006-01-02T15:04:05.000"
	beginMessage          = []byte("-----BEGIN CANARY SIGNED MESSAGE-----")
	endMessage            = []byte("-----END CANARY SIGNED MESSAGE-----")
	beginSignature        = []byte("-----BEGIN SIGNATURE-----")
)

func parseMessage(canary []byte) (*Message, error) {

	// locate message bytes
	i := bytes.Index(canary, beginMessage)
	if i < 0 {
		return nil, &ConsoleError{Message: "failed to parse canary message"}
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
	var err error
	if err = json.Unmarshal(canary, &msg); err != nil {
		return nil, &ConsoleError{Message: "failed to parse canary message", Err: err}
	}

	msg.ReleaseDate, err = time.Parse(timeLayout, msg.Release)
	if err != nil {
		return nil, &ConsoleError{Message: "failed to parse canary release date", Err: err}
	}
	msg.ExpireDate, err = time.Parse(timeLayout, msg.Expire)
	if err != nil {
		return nil, &ConsoleError{Message: "failed to parse canary expire date", Err: err}
	}

	return &msg, nil
}
