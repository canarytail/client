package main

import (
	"bytes"
	"encoding/json"
	"errors"
)

var (
	beginMessage   = []byte("-----BEGIN CANARY SIGNED MESSAGE-----")
	beginSignature = []byte("-----BEGIN SIGNATURE-----")

	errCanaryParse = errors.New("failed to parse canary message")
)

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
