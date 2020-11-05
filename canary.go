package canarytail

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// TimestampLayout defines the timestamp layout used in the standard
//const TimestampLayout string = "2006-01-02T15:04:05.000" // time.RFC3339 should be preferred (what we have plus Z)
const TimestampLayout string = time.RFC3339

// StandardVersion represents the current standard version being used by this library
const StandardVersion string = "0.1"

// CanaryClaim the claims that conform this canary
type CanaryClaim struct {
	Domain      string   `json:"DOMAIN"`
	PubKey      string   `json:"PUBKEY"`
	NewPubKey   string   `json:"NEWPUBKEY"`
	PanicKey    string   `json:"PANICKEY"`
	NewPanicKey string   `json:"NEWPANICKEY"`
	Version     string   `json:"VERSION"`
	Release     string   `json:"RELEASE"` // 2019-03-06T22:23:09.963
	Expire      string   `json:"EXPIRY"`  // 2019-03-06T22:23:09.963
	Freshness   string   `json:"FRESHNESS"`
	Codes       []string `json:"CODES"`
}

// CanarySignature we will keep this as a string for now, in the future it will support several signatures
type CanarySignature string

// Canary represents a Canary, with its claims and its signature(s)
type Canary struct {
	Claim     CanaryClaim     `json:"CANARY"`
	Signature CanarySignature `json:"SIGNATURE"`
}

// AllCodes lists all Canary codes
// TODO: support multiple standard versions
func AllCodes() []string {
	return []string{
		"WAR",    // Warrants
		"GAG",    // Gag orders
		"SUBP",   // Subpoenas
		"TRAP",   // Trap and trace orders
		"CEASE",  // Court order to cease operations
		"DURESS", // Coercion, blackmail, or otherwise operating under duress
		"RAID",   // Raids with high confidence nothing containing useful data was seized
		"SEIZE",  // Raids with low confidence nothing containing useful data was seized
		"XCRED",  // Compromised credentials
		"XOPERS", // Compromised operations
		"SEPPU",  // Seppuku pledge²
	}
}

// ExiprationTimestamp parses the expiration timestamp within this canary claims
func (c Canary) ExiprationTimestamp() time.Time {
	t, _ := time.Parse(TimestampLayout, c.Claim.Expire)
	return t
}

// ReleaseTimestamp parses the expiration timestamp within this canary claims
func (c Canary) ReleaseTimestamp() time.Time {
	t, _ := time.Parse(TimestampLayout, c.Claim.Release)
	return t
}

// IsExpired checks whether the canary is expired
func (c Canary) IsExpired() bool {
	t := c.ExiprationTimestamp()
	return t.Before(time.Now())
}

// MissingCodes gets the missing codes from this Canary's claims
func (c Canary) MissingCodes() []string {
	codes := make(map[string]bool)
	allCodes := AllCodes()
	for i := range allCodes {
		code := allCodes[i]
		codes[code] = true
	}

	for i := range c.Claim.Codes {
		code := c.Claim.Codes[i]
		codes[code] = false
	}

	missingCodes := make([]string, 0)
	for code, missing := range codes {
		if missing {
			missingCodes = append(missingCodes, code)
		}
	}
	return missingCodes
}

// Validate validates if the Canary claims indicate some sort of issue
func (c Canary) Validate() bool {
	publicKey, err := ParsePublicKey(c.Claim.PubKey)
	if err != nil {
		fmt.Printf("Could not validate the canary: the public key cannot be parsed: %v\n", err)
		return false
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(string(c.Signature))
	if !ValidateSignature(c, signatureBytes, publicKey) {
		fmt.Printf("Could not validate the canary: the signature could not be validated: %v\n", err)
		return false
	}

	// check if expired
	if c.IsExpired() {
		fmt.Printf("Could not validate the canary: the canary has expired\n")
		return false
	}

	// check if released in the future
	if time.Now().Before(c.ReleaseTimestamp()) {
		fmt.Printf("Could not validate the canary: the canary is released with a date in the future: %v vs %v\n", time.Now(), c.ReleaseTimestamp())
		return false
	}

	// check if the block exists in the blockchain
	blockHash, err := hex.DecodeString(c.Claim.Freshness)
	blockInfo, err := GetBlockInfo(blockHash)
	if err != nil {
		fmt.Printf("Could not validate the canary: the block provided seems not to be valid, or there is an issue retrieving the block info: %v\n", err)
		return false
	}

	// check block's freshness in the blockchain (compare against Release claim? 1h tolerance?)
	blockReleasedTime := time.Unix(blockInfo.Time, 0)
	if c.ReleaseTimestamp().Sub(blockReleasedTime) > time.Hour*1 {
		fmt.Printf("Could not validate the canary: the block provided was more than 1h older than the release date of the canary\n")
		return false
	}

	// TODO: check if it has been signed by the panic key, if any

	missingCodes := c.MissingCodes()
	if len(missingCodes) > 0 {
		fmt.Printf("Could not validate the canary: some codes are missing: %v\n", missingCodes)
		return false
	}

	return true
}

// Format gets the JSON representation of the canary
func (c Canary) Format() string {
	contents, _ := json.MarshalIndent(&c, "", "    ")
	return string(contents)
}

// InverseCodes returns the missing codes from the standard, given a list of codes
// TODO: validate the codes supplied and error out on invalid codes
func InverseCodes(codesToFlag []string) []string {
	codes := make(map[string]bool)
	allCodes := AllCodes()
	for i := range allCodes {
		code := allCodes[i]
		codes[code] = true
	}

	for i := range codesToFlag {
		code := codesToFlag[i]
		codes[code] = false
	}

	missingCodes := make([]string, 0)
	for code, missing := range codes {
		if missing {
			missingCodes = append(missingCodes, code)
		}
	}
	return missingCodes
}
