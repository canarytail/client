package canarytail

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	PublicKeys []string `json:"pubkeys"`
	PanicKey   string   `json:"panickey"`
	Version    string   `json:"version"`
	Release    string   `json:"release"` // 2019-03-06T22:23:09.963
	Expiry     string   `json:"expiry"`  // 2019-03-06T22:23:09.963
	Freshness  string   `json:"freshness"`
	Codes      []string `json:"codes"`
	IPNSKey    *string  `json:"ipns_key,omitempty"`
}

// CanarySignature we will keep this as a string for now, in the future it will support several signatures
type CanarySignature string

type CanarySignatureSet struct {
	Domain     CanarySignature  `json:"domain"`
	PublicKeys CanarySignature  `json:"pubkeys"`
	PanicKey   CanarySignature  `json:"panickey"`
	Version    CanarySignature  `json:"version"`
	Release    CanarySignature  `json:"release"`
	Expiry     CanarySignature  `json:"expiry"`
	Freshness  CanarySignature  `json:"freshness"`
	Codes      CanarySignature  `json:"codes"`
	IPNSKey    *CanarySignature `json:"ipns_key,omitempty"`
}

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
	Canary         Canary
	Validators     []CanarySignatureValidator
	PanicValidator CanarySignatureValidator
}

// NewCanaryValidator instantiates a CanaryValidator
func NewCanaryValidator(canary Canary) (validator *CanaryValidator) {
	validator = &CanaryValidator{
		Canary:     canary,
		Validators: make([]CanarySignatureValidator, 0),
		PanicValidator: CanarySignatureValidator{
			Canary:    canary,
			PublicKey: canary.Claim.PanicKey,
		},
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

// Validate validates all the registered validators (one per public key in the canary plus the panic key)
func (v *CanaryValidator) Validate() (bool, error) {
	// check if the panic key has signed
	if ok, _ := v.PanicValidator.Validate(); ok {
		return false, fmt.Errorf("The panic key %s was used to sign the canary", v.PanicValidator.PublicKey)
	}
	// validate wether all the public keys have signed or not
	for _, validator := range v.Validators {
		if ok, err := validator.Validate(); !ok {
			return false, err
		}
	}
	return true, nil
}

// CanarySignatureValidator validates an ECDSA (​Curve25519​) set of signatures for a given canary and a public key
type CanarySignatureValidator struct {
	Canary    Canary
	PublicKey string
}

// Validate a signature set for a given public key
func (v *CanarySignatureValidator) Validate() (bool, error) {
	pubKey, err := ParsePublicKey(v.PublicKey)
	if err != nil {
		return false, err
	}
	ok := v.Canary.ValidateSignatures(pubKey)
	if !ok {
		err = fmt.Errorf("Signature verification failed for key %s", v.PublicKey)
	}
	return ok, err
}

// Canary represents a Canary, with its claims and its signature(s)
type Canary struct {
	Claim      CanaryClaim                    `json:"canary"`
	Signatures map[string]*CanarySignatureSet `json:"signatures"` // the key of the map is the public key that signs the signature set
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

// Sign generates the signatures of all the canary claims for a given public key
func (c *Canary) Sign(privKey, pubKey []byte) (err error) {
	if c.Signatures == nil {
		c.Signatures = make(map[string]*CanarySignatureSet)
	}

	pubKeyEncoded := FormatKey(pubKey)
	c.Signatures[pubKeyEncoded] = &CanarySignatureSet{}
	signatureSet := c.Signatures[pubKeyEncoded]

	// Sign the fields
	if signatureSet.Domain, err = c.signField(c.Claim.Domain, privKey); err != nil {
		return
	}
	if signatureSet.PublicKeys, err = c.signField(c.Claim.PublicKeys, privKey); err != nil {
		return
	}
	if signatureSet.PanicKey, err = c.signField(c.Claim.PanicKey, privKey); err != nil {
		return
	}
	if signatureSet.Version, err = c.signField(c.Claim.Version, privKey); err != nil {
		return
	}
	if signatureSet.Release, err = c.signField(c.Claim.Release, privKey); err != nil {
		return
	}
	if signatureSet.Expiry, err = c.signField(c.Claim.Expiry, privKey); err != nil {
		return
	}
	if signatureSet.Freshness, err = c.signField(c.Claim.Freshness, privKey); err != nil {
		return
	}
	if signatureSet.Codes, err = c.signField(c.Claim.Codes, privKey); err != nil {
		return
	}
	if c.Claim.IPNSKey != nil && *c.Claim.IPNSKey != "" {
		ipnsKeySign, err := c.signField(*c.Claim.IPNSKey, privKey)
		if err != nil {
			return err
		}
		signatureSet.IPNSKey = &ipnsKeySign
	}
	return
}

func (c *Canary) validateSignature(value interface{}, signatureEnc CanarySignature, pubKey []byte) bool {
	signature, err := base64.StdEncoding.DecodeString(string(signatureEnc))
	if err != nil {
		return false
	}
	stdValue := c.standardFieldValue(value)
	return ValidateSignatureString(stdValue, signature, pubKey)

}

// ValidateSignatures validates the signatures of a canary for a given public key
func (c *Canary) ValidateSignatures(pubKey []byte) bool {

	pubKeyEncoded := FormatKey(pubKey)

	signatureSet, ok := c.Signatures[pubKeyEncoded]
	if !ok {
		return false // the public key is not part of the signature set
	}

	// validate each signature
	if !c.validateSignature(c.Claim.Domain, signatureSet.Domain, pubKey) {
		return false
	}
	if !c.validateSignature(c.Claim.PublicKeys, signatureSet.PublicKeys, pubKey) {
		return false
	}
	if !c.validateSignature(c.Claim.PanicKey, signatureSet.PanicKey, pubKey) {
		return false
	}
	if !c.validateSignature(c.Claim.Version, signatureSet.Version, pubKey) {
		return false
	}
	if !c.validateSignature(c.Claim.Release, signatureSet.Release, pubKey) {
		return false
	}
	if !c.validateSignature(c.Claim.Expiry, signatureSet.Expiry, pubKey) {
		return false
	}
	if !c.validateSignature(c.Claim.Freshness, signatureSet.Freshness, pubKey) {
		return false
	}
	if !c.validateSignature(c.Claim.Codes, signatureSet.Codes, pubKey) {
		return false
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

func (c *Canary) signField(value interface{}, privKey []byte) (CanarySignature, error) {
	// represent the value as a string
	valueStr := c.standardFieldValue(value)
	signatureRaw := SignString(valueStr, privKey)
	signature := base64.StdEncoding.EncodeToString(signatureRaw)
	return CanarySignature(signature), nil
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
		code := strings.ToLower(c.Claim.Codes[i])
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
	if len(c.Claim.PanicKey) > 0 {
		panicKey = c.Claim.PanicKey
	}
	if len(panicKey) > 0 {
		panicKeyBytes, _ := ParsePublicKey(panicKey)
		return panicKeyBytes
	}
	return nil
}

// Validate validates if the Canary claims indicate some sort of issue
func (c Canary) Validate() (bool, error) {
	// validate the signatures with the public key
	validator := NewCanaryValidator(c)
	if ok, err := validator.Validate(); !ok {
		return false, err
	}

	// check if the canary has expired
	if c.IsExpired() {
		return false, fmt.Errorf("Could not validate the canary: the canary has expired")
	}

	// check if the canary has been released in the future
	if time.Now().Before(c.ReleaseTimestamp()) {
		return false, fmt.Errorf("Could not validate the canary: the canary is released with a date in the future: %v vs %v", time.Now(), c.ReleaseTimestamp())
	}

	// check if the reported block exists in the blockchain
	blockHash, err := hex.DecodeString(c.Claim.Freshness)
	if err != nil {
		return false, fmt.Errorf("Could not validate the canary: the block provided seems not to be valid, or there is an issue retrieving the block info: %v", err)
	}
	blockInfo, err := GetBlockInfo(blockHash)
	if err != nil {
		return false, fmt.Errorf("Could not validate the canary: the block provided seems not to be valid, or there is an issue retrieving the block info: %v", err)
	}

	// check block's freshness in the blockchain (compare against Release claim? 1h tolerance?)
	blockReleasedTime := time.Unix(blockInfo.Time, 0)
	if c.ReleaseTimestamp().Sub(blockReleasedTime) > time.Hour*1 {
		return false, fmt.Errorf("Could not validate the canary: the block provided was more than 1h older than the release date of the canary")
	}

	// check for missing codes in the canary, which will trigger its failure
	missingCodes := c.MissingCodes()
	if len(missingCodes) > 0 {
		return false, fmt.Errorf("Could not validate the canary: some codes are missing: %v", missingCodes)
	}

	return true, nil
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
		code := strings.ToLower(codesToFlag[i])
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
