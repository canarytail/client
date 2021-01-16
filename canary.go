package canarytail

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// TimestampLayout defines the timestamp layout used in the standard
//const TimestampLayout string = "2006-01-02T15:04:05.000" // time.RFC3339 should be preferred (what we have plus Z)
const TimestampLayout string = time.RFC3339

// StandardVersion represents the current standard version being used by this library
const StandardVersion string = "0.1"

// CanaryClaim the claims that conform this canary
type CanaryClaim struct {
	Domain     string   `json:"domain"`
	PubKey     string   `json:"pubkey"`
	PublicKeys []string `json:"pubkeys"`
	//	NewPubKey   string   `json:"newpubkey"`
	PanicKey string `json:"panickey"`
	//	NewPanicKey string   `json:"newpanickey"`
	Version   string   `json:"version"`
	Release   string   `json:"release"` // 2019-03-06T22:23:09.963
	Expiry    string   `json:"expiry"`  // 2019-03-06T22:23:09.963
	Freshness string   `json:"freshness"`
	Codes     []string `json:"codes"`
}

// CanarySignature we will keep this as a string for now, in the future it will support several signatures
type CanarySignature string

// StructToMap converts a struct to a map while maintaining the json alias as keys
func StructToMap(obj interface{}) (newMap map[string]interface{}, err error) {
	data, err := json.Marshal(obj) // Convert to a json string

	if err != nil {
		return
	}

	err = json.Unmarshal(data, &newMap) // Convert to a map
	return
}

// CanaryValidator validates a canary
type CanaryValidator struct {
	Canary     Canary
	Validators []CanarySignatureValidator
}

// NewCanaryValidator instantiates a CanaryValidator
func NewCanaryValidator(canary Canary) (validator *CanaryValidator) {
	validator = &CanaryValidator{
		Canary:     canary,
		Validators: make([]CanarySignatureValidator, 0),
	}

	// Security level LOW
	// The canary can be authenticated to the original source by providing the DOMAIN it will be served at.
	// This is a less secure method of authenticity as anyone with publishing access to the domain can modify the canary.

	// Security levels MEDIUM and HIGH: they differentiate on the amount of keys involved in the process
	// extract all public keys to be validates in the canary and create a validator for each
	for _, pubKey := range canary.Claim.PublicKeys {
		validator.Validators = append(validator.Validators, CanarySignatureValidator{
			Canary:    canary,
			PublicKey: pubKey,
		})
	}
	return
}

func (v *CanaryValidator) Validate() bool {
	for _, validator := range v.Validators {
		if !validator.Validate() {
			return false
		}
	}
	return true
}

// CanarySignatureValidator validates an ECDSA (​Curve25519​) set of signatures for a given canary and a public key
type CanarySignatureValidator struct {
	Canary    Canary
	PublicKey string
}

func (v *CanarySignatureValidator) Validate() bool {
	// TODO: Implament signature validator for a given pubKey
	// get all the relevant signatures
	// make sure none is missing
	// validate each one of them against this pubKey
	pubKey, err := base64.StdEncoding.DecodeString(v.PublicKey)
	if err != nil {
		return false
	}
	return v.Canary.ValidateSignatures(pubKey)
}

// Canary represents a Canary, with its claims and its signature(s)
type Canary struct {
	Claim      CanaryClaim                `json:"canary"`
	Signatures map[string]CanarySignature `json:"signatures"`
}

// AllCodes lists all Canary codes
// TODO: support multiple standard versions
func AllCodes() []string {
	return []string{
		"war",    // Warrants
		"gag",    // Gag orders
		"subp",   // Subpoenas
		"trap",   // Trap and trace orders
		"cease",  // Court order to cease operations
		"duress", // Coercion, blackmail, or otherwise operating under duress
		"raid",   // Raids with high confidence nothing containing useful data was seized
		"seize",  // Raids with low confidence nothing containing useful data was seized
		"xcred",  // Compromised credentials
		"xopers", // Compromised operations
	}
}

// Sign generates the signatures of all the canary claims
func (c *Canary) Sign(privKey []byte) error {
	t := reflect.TypeOf(c.Claim)
	v := reflect.ValueOf(c.Claim)
	fields := make([]string, 0)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldName := strings.ToUpper(field.Name)
		fields = append(fields, fieldName)
	}

	var err error
	c.Signatures = make(map[string]CanarySignature)
	for i, field := range fields {
		c.Signatures[field], err = c.signField(field, v.Field(i).Interface(), privKey)
		if err != nil {
			return err
		}
	}
	return nil
}

// ValidateSignatures validates the signatures of a canary
func (c *Canary) ValidateSignatures(pubKey []byte) bool {
	// list all claim fields (each field must have a matching signature which we will have to validate)
	t := reflect.TypeOf(c.Claim)
	v := reflect.ValueOf(c.Claim)
	fields := make([]string, 0)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldName := strings.ToUpper(field.Name)
		fields = append(fields, fieldName)
	}

	// validate each signature
	for i, field := range fields {
		signatureEnc, ok := c.Signatures[field]
		if !ok {
			// the signature is missing => what to do in this case? whitelist some? expect all?
			return false
		}

		signature, err := base64.StdEncoding.DecodeString(string(signatureEnc))
		if err != nil {
			return false
		}

		value := c.standardFieldValue(v.Field(i).Interface())
		if !ValidateSignatureString(value, signature, pubKey) {
			return false
		}
	}
	return true
}

// standarizes the value of a field for signing, as a string
func (c *Canary) standardFieldValue(v interface{}) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case []string:
		return strings.Join(x, " ")
	case string:
		return x
	default:
		return fmt.Sprintf("%v", x)
	}
}

func (c *Canary) signField(name string, value interface{}, privKey []byte) (CanarySignature, error) {
	// represent the value as a string
	valueStr := c.standardFieldValue(value)
	signatureRaw := SignString(valueStr, privKey)
	signature := base64.StdEncoding.EncodeToString(signatureRaw)
	return CanarySignature(signature), nil
}

// MarshalJSON writes the JSON value of the Canary, with all the signatures
func (c *Canary) MarshalJSON() ([]byte, error) {
	v, err := StructToMap(c.Claim)
	if err != nil {
		return nil, err
	}

	claims := make(map[string]interface{})
	for k, v := range v {
		claims[k] = v
		signature, ok := c.Signatures[k]
		if ok {
			claims["signed_"+k] = signature
		}
	}
	return json.Marshal(claims)
}

// UnmarshalJSON reads the JSON
func (c *Canary) UnmarshalJSON(data []byte) error {
	var v map[string]interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	claims := make(map[string]interface{})
	for k, v := range v {
		claims[k] = v
	}

	c.Signatures = make(map[string]CanarySignature)

	// extract signatures
	for k, v := range v {
		if strings.HasPrefix(k, "signed_") {
			field := strings.TrimPrefix(k, "signed_")
			signature, ok := v.(string)
			if !ok {
				return errors.New("Error parsing signature from JSON")
			}
			c.Signatures[field] = CanarySignature(signature)
			delete(claims, k)
		}
	}

	// extract claims
	claimsString, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(claimsString, &c.Claim); err != nil {
		return err
	}

	return nil
}

// ExiprationTimestamp parses the expiration timestamp within this canary claims
func (c Canary) ExiprationTimestamp() time.Time {
	t, _ := time.Parse(TimestampLayout, c.Claim.Expiry)
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

// PanicKey returns the most current panic key of the canary
func (c Canary) PanicKey() []byte {
	panicKey := ""
	if len(c.Claim.NewPanicKey) > 0 {
		panicKey = c.Claim.NewPanicKey
	} else if len(c.Claim.PanicKey) > 0 {
		panicKey = c.Claim.PanicKey
	}
	if len(panicKey) > 0 {
		panicKeyBytes, _ := ParsePublicKey(panicKey)
		return panicKeyBytes
	}
	return nil
}

// Validate validates if the Canary claims indicate some sort of issue
func (c Canary) Validate() bool {
	publicKey, err := ParsePublicKey(c.Claim.PubKey)
	if err != nil {
		fmt.Printf("Could not validate the canary: the public key cannot be parsed: %v\n", err)
		return false
	}

	// validate the signatures with the public key
	validator := NewCanaryValidator(c)
	if !validator.Validate() {
		// check if it has been signed by the panic key, if any
		panicKey := c.PanicKey()
		if panicKey != nil && c.ValidateSignatures(panicKey) {
			fmt.Printf("The canary has been signed with the panic key!\n")
			return false
		}

		fmt.Printf("Could not validate the canary: the signatures are not valid\n")
		return false
	}

	// check if the canary has expired
	if c.IsExpired() {
		fmt.Printf("Could not validate the canary: the canary has expired\n")
		return false
	}

	// check if the canary has been released in the future
	if time.Now().Before(c.ReleaseTimestamp()) {
		fmt.Printf("Could not validate the canary: the canary is released with a date in the future: %v vs %v\n", time.Now(), c.ReleaseTimestamp())
		return false
	}

	// check if the reported block exists in the blockchain
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

	// check for missing codes in the canary, which will trigger its failure
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

func validateCodes(codesToValidate []string) bool {
	allCodes := AllCodes()
	for i := range codesToValidate {
		valid := false
		code := strings.ToUpper(codesToValidate[i])
		for j := range allCodes {
			if allCodes[j] == code {
				valid = true
				break
			}
		}
		if !valid {
			return false
		}
	}
	return true
}

// InverseCodes returns the missing codes from the standard, given a list of codes
func InverseCodes(codesToFlag []string) []string {
	codes := make(map[string]bool)
	allCodes := AllCodes()
	for i := range allCodes {
		code := allCodes[i]
		codes[code] = true
	}

	// TODO: validate the codes supplied and error out on invalid codes?
	//if !validateCodes(codesToFlag) {
	//	return nil
	//}

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
