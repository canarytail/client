package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	canarytail "github.com/canarytail/client"
)

const version = "0.1"

type context struct {
	Debug bool
}

var cli struct {
	Debug bool `help:"Enable debug mode."`

	Init initCmd `cmd help:"Initialize config and keys to $CANARY_HOME"`

	Key struct {
		New keyNewCmd `cmd help:"Generates a new key for signing canaries and saves to $CANARY_HOME/DOMAIN"`
	} `cmd help:"This command is for manipulating cryptographic keys."`

	Canary struct {
		New      canaryNewCmd      `cmd help:"Generates a new canary, signs it using the key located in $CANARY_HOME/DOMAIN, and saves to that same path.  Codes provided in OPTIONS will be removed from the canary, signifying that event has triggered the canary."`
		Update   canaryUpdateCmd   `cmd help:"Updates the existing canary named DOMAIN. If no OPTIONS are provided, it merely updates the signature date. If no EXPIRY is provided, it reuses the previous value (e.g. renewing for a month).  Codes provided in OPTIONS will be removed from the canary, signifying that event has triggered the canary."`
		Panic    canaryPanicCmd    `cmd help:"Updates the existing canary named ALIAS. The canary is signed with the panic key, which will ensure the canary validation fails in all cases."`
		Validate canaryValidateCmd `cmd help:"Validates a canary's signature"`
		Sign     canarySignCmd     `cmd help:"Sign's a canary with keys stored in $CANARY_HOME/DOMAIN"`
		Pubkey   canaryPubkeyCmd   `cmd help:"Print your public key for the domain. Use 'key new' command to create one if it does not exist."`
	} `cmd help:"This command is for manipulating canaries."`

	Version versionCmd `cmd help:"Show version and exit"`
}

func main() {
	ctx := kong.Parse(&cli, kong.UsageOnError())
	err := ctx.Run(&context{Debug: cli.Debug})
	ctx.FatalIfErrorf(err)
}

type initCmd struct {
}

func (cmd *initCmd) Run(ctx *context) error {
	dir := canaryHomeDir()
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return os.Mkdir(dir, 0700)
	}
	return nil
}

type keyCmd struct {
	New keyNewCmd `cmd help:"Generates a new key for signing canaries and saves to $CANARY_HOME/ALIAS"`
}

type keyNewCmd struct {
	Domain string `arg name:"DOMAIN" help:"Domain of the canary"`
}

func (cmd *keyNewCmd) Run(ctx *context) error {
	stagingPath := canaryDirSafe(cmd.Domain)

	fmt.Printf("Generating signing key pair for %v at %v...\n", cmd.Domain, stagingPath)
	defer fmt.Println("Done.")

	publicKey, privateKey, err := canarytail.GenerateKeyPair()
	if err != nil {
		panic(fmt.Errorf("Could not generate key pair: %v", err))
	}

	err = writeToFile(path.Join(stagingPath, "public.b64"), base64.StdEncoding.EncodeToString(publicKey))
	if err != nil {
		return err
	}

	err = writeToFile(path.Join(stagingPath, "private.b64"), base64.StdEncoding.EncodeToString(privateKey))
	if err != nil {
		return err
	}

	fmt.Printf("Generating panic key pair for %v at %v...\n", cmd.Domain, stagingPath)

	publicPanicKey, privatePanicKey, err := canarytail.GenerateKeyPair()
	if err != nil {
		panic(fmt.Errorf("Could not generate panic key pair: %v", err))
	}

	err = writeToFile(path.Join(stagingPath, "panic-public.b64"), base64.StdEncoding.EncodeToString(publicPanicKey))
	if err != nil {
		return err
	}

	err = writeToFile(path.Join(stagingPath, "panic-private.b64"), base64.StdEncoding.EncodeToString(privatePanicKey))
	if err != nil {
		return err
	}

	return nil
}

type canaryOpCmd struct {
	Domain string `arg name:"DOMAIN"`

	Expiry     int      `name:"expiry" help:"Expires in # minutes from now (default: 43200, one month)" default:"43200"`
	GAG        bool     `name:"GAG" help:"Gag order received"`
	TRAP       bool     `name:"TRAP" help:"Trap and trace order received"`
	DURESS     bool     `name:"DURESS" help:"Under duress (coercion, blackmail, etc)"`
	XCRED      bool     `name:"XCRED" help:"Compromised credentials"`
	XOPERS     bool     `name:"XOPERS" help:"Operations compromised"`
	WAR        bool     `name:"WAR" help:"Warrant received"`
	SUBP       bool     `name:"SUBP" help:"Subpoena received"`
	CEASE      bool     `name:"CEASE" help:"Court order to cease operations"`
	RAID       bool     `name:"RAID" help:"Raided, but data unlikely compromised"`
	SEIZE      bool     `name:"SEIZE" help:"Hardware or data seized, unlikely compromised"`
	MinSigners int      `name:"min-signers" help:"Minimum number of signers that are required to sign the canary for it to be valid (default and minimum allowed is 1)"`
	Signers    []string `name:"signers" help:"List of all the signers that can sign this canary in the format 'name1:pubkey1,name2:pubkey2:required,name3:pubkey3,...'. Here the optional ':required' means that the signer is required to sign the canary. Mentioning author's public key is optional and should be used to only add a signer name to the author. Use this to also replace the list of signers."`
}

func getCodes(cmd canaryOpCmd) []string {
	codes := make([]string, 0)
	if cmd.GAG {
		codes = append(codes, "gag")
	}
	if cmd.TRAP {
		codes = append(codes, "trap")
	}
	if cmd.DURESS {
		codes = append(codes, "duress")
	}
	if cmd.XCRED {
		codes = append(codes, "xcred")
	}
	if cmd.XOPERS {
		codes = append(codes, "xopers")
	}
	if cmd.WAR {
		codes = append(codes, "war")
	}
	if cmd.SUBP {
		codes = append(codes, "subp")
	}
	if cmd.CEASE {
		codes = append(codes, "cease")
	}
	if cmd.RAID {
		codes = append(codes, "raid")
	}
	if cmd.SEIZE {
		codes = append(codes, "seize")
	}
	return canarytail.InverseCodes(codes)
}

type keyPairReader func(dir string) (ed25519.PublicKey, ed25519.PrivateKey, error)

func generateCanary(cmd canaryOpCmd, signingKeyPairReader keyPairReader) error {
	dir := canaryDirSafe(cmd.Domain)

	// read the key pair for this canary alias
	publickKey, _, err := readKeyPair(dir)
	if err != nil {
		return err
	}

	// read the panic key pair for this canary alias
	publicPanicKey, _, err := readPanicKeyPair(dir)
	if err != nil {
		return err
	}

	// read the key pair for this canary alias
	publicSigningKey, privateSigningKey, err := signingKeyPairReader(dir)
	if err != nil {
		return err
	}

	if cmd.MinSigners < 1 {
		cmd.MinSigners = 1
	}
	canaryTime := time.Now()
	authorKey := canarytail.FormatKey(publickKey)
	// compose the canary
	canary := &canarytail.Canary{
		Version: canarytail.StandardVersion,
		Claim: canarytail.CanaryClaim{
			Domain:     cmd.Domain,
			MinSigners: cmd.MinSigners,
			Codes:      getCodes(cmd),
			Release:    canaryTime.Format(canarytail.TimestampLayout),
			Freshness:  canarytail.GetLastBlockChainBlockHashFormatted(),
			Expiry:     canaryTime.Add(time.Duration(cmd.Expiry) * time.Minute).Format(canarytail.TimestampLayout),
			PublicKeys: []canarytail.PublicKey{
				{
					Role:     canarytail.RoleAuthor,
					Key:      authorKey,
					Required: true,
				},
			},
			PanicKey: canarytail.FormatKey(publicPanicKey),
		},
	}

	signers, err := decodeSigners(cmd.Signers)
	if err != nil {
		return err
	}
	// If the 'signers' has the author, update the name of author.
	for _, s := range signers {
		if s.Key == authorKey {
			// This is the author.
			canary.Claim.PublicKeys[0].Name = s.Name
			continue
		}
		canary.Claim.PublicKeys = append(canary.Claim.PublicKeys, s)
	}
	if canary.Claim.PublicKeys[0].Name == "" {
		canary.Claim.PublicKeys[0].Name = canarytail.RoleAuthor
	}

	if len(canary.Claim.PublicKeys) < canary.Claim.MinSigners {
		return fmt.Errorf(
			"total number of signers should be at least min signers, min_signers=%d, total=%d",
			canary.Claim.MinSigners, len(canary.Claim.PublicKeys),
		)
	}

	// sign it
	err = canary.Sign(privateSigningKey, publicSigningKey)
	if err != nil {
		return err
	}

	// and print it
	fileName := canaryFileName(canary.Claim.Domain, canaryTime)
	latestFileName := canaryLatestFileName(canary.Claim.Domain)
	canaryFormatted := canary.Format()
	fp := path.Join(dir, fileName)
	if err := writeToFile(fp, canaryFormatted); err != nil {
		return err
	}
	fp = path.Join(dir, latestFileName)
	if err := writeToFile(fp, canaryFormatted); err != nil {
		return err
	}

	absFp, err := filepath.Abs(fp)
	if err != nil {
		absFp = fp
	}
	fmt.Printf("New canary has been stored at %q\n", absFp)
	printNextSignerSuggestion(canary)
	return nil
}

func decodeSigners(ss []string) ([]canarytail.PublicKey, error) {
	signers := make(map[string]canarytail.PublicKey, len(ss))

	for _, s := range ss {
		parts := strings.Split(s, ":")
		if len(parts) < 2 {
			return nil, fmt.Errorf("malformed signer, expected at least 2 ':' separated parts in %s", s)
		}
		if len(parts) > 3 {
			return nil, fmt.Errorf("malformed signer, expected less than 3 ':' separated parts in %s", s)
		}
		if len(parts) == 3 && parts[2] != "required" {
			return nil, fmt.Errorf("malformed signer, expected 'required' in the third part in %s", s)
		}

		if _, ok := signers[parts[0]]; ok {
			return nil, fmt.Errorf("duplicate signer found with the name %s", parts[0])
		}

		signers[parts[0]] = canarytail.PublicKey{
			Role:     canarytail.RoleCosigner,
			Name:     parts[0],
			Key:      parts[1],
			Required: len(parts) == 3, // parts[2] is already checked above.
		}
	}

	signerSlice := make([]canarytail.PublicKey, 0, len(signers))
	for _, s := range signers {
		signerSlice = append(signerSlice, s)
	}

	signerSlice = sortSigners(signerSlice)

	return signerSlice, nil
}

func sortSigners(signers []canarytail.PublicKey) []canarytail.PublicKey {
	// This sorting first groups the required and non-required together and
	// sorts based on their signer name within the group.
	sort.Slice(signers, func(i, j int) bool {
		a, b := signers[i], signers[j]
		if a.Required == b.Required {
			return a.Name < b.Name
		}
		return a.Required
	})

	return signers
}

func printNextSignerSuggestion(c *canarytail.Canary) {
	signCriteriaMet := len(c.Signatures) >= c.Claim.MinSigners
	nextSigner := ""
	for _, pubKey := range c.Claim.PublicKeys {
		_, ok := c.Signatures[pubKey.Key]
		if pubKey.Required && !ok {
			signCriteriaMet = false
		}
		if nextSigner == "" && !ok {
			nextSigner = pubKey.Name
		}
	}

	if signCriteriaMet && nextSigner == "" {
		// All signers are done.
		fmt.Printf("Everyone has finished signing, please send the canary back to %s.\n", canarytail.RoleAuthor)
	} else if signCriteriaMet && nextSigner != "" {
		// Criteria met but signers are left.
		fmt.Printf(
			"Signing criteria has met. You can either send the canary back to %s, or send it to %q for further signing.\n",
			canarytail.RoleAuthor, nextSigner,
		)
	} else {
		// Criteria not met.
		fmt.Printf("Please send the canary to %q for further signing.\n", nextSigner)
	}
}

func updateCanary(cmd canaryOpCmd, signingKeyPairReader keyPairReader) error {
	dir := canaryDirSafe(cmd.Domain)

	fileName, err := getLatestCanaryFileName(dir)
	if err != nil {
		return err
	}
	canary, err := readCanaryFile(path.Join(dir, fileName))
	if err != nil {
		return err
	}

	// read the panic key pair for this canary alias
	publicPanicKey, _, err := readPanicKeyPair(dir)
	if err != nil {
		return err
	}

	// read the key pair for this canary alias
	publicSigningKey, privateSigningKey, err := signingKeyPairReader(dir)
	if err != nil {
		return err
	}

	if cmd.MinSigners < 1 {
		cmd.MinSigners = 1
	}

	// update the canary
	canaryTime := time.Now()
	canary.Claim.MinSigners = cmd.MinSigners
	canary.Claim.Release = canaryTime.Format(canarytail.TimestampLayout)
	canary.Claim.Freshness = canarytail.GetLastBlockChainBlockHashFormatted()
	canary.Claim.Expiry = canaryTime.Add(time.Duration(cmd.Expiry) * time.Minute).Format(canarytail.TimestampLayout)
	canary.Version = canarytail.StandardVersion
	canary.Claim.Codes = getCodes(cmd)

	// if the public key is not there, add it
	publicKeyEnc := canarytail.FormatKey(publicSigningKey)
	if publicKeyEnc != canary.Claim.PanicKey {
		foundPubKey := false
		for _, x := range canary.Claim.PublicKeys {
			if x.Key == publicKeyEnc {
				foundPubKey = true
				break
			}
		}
		if !foundPubKey {
			// First signers is the author.
			canary.Claim.PublicKeys = append([]canarytail.PublicKey{{
				Role:     canarytail.RoleAuthor,
				Key:      publicKeyEnc,
				Required: true,
			}}, canary.Claim.PublicKeys...)
		}
	}

	// if the panic key is not the same, error out
	panicKeyEnc := canarytail.FormatKey(publicPanicKey)
	if panicKeyEnc == publicKeyEnc && panicKeyEnc != canary.Claim.PanicKey {
		return errors.New("The panic key does not match")
	}

	signers, err := decodeSigners(cmd.Signers)
	if err != nil {
		return err
	}

	if len(signers) != 0 {
		// Since signers are being updated, we discard all the old signers except author.
		// This allows editing old signers too.
		canary.Claim.PublicKeys = canary.Claim.PublicKeys[:1]
	}

	// If the 'signers' has the author, update the name of author.
	for _, s := range signers {
		if s.Key == publicKeyEnc {
			// This is the author.
			canary.Claim.PublicKeys[0].Name = s.Name
			continue
		}
		canary.Claim.PublicKeys = append(canary.Claim.PublicKeys, s)
	}
	if canary.Claim.PublicKeys[0].Name == "" {
		canary.Claim.PublicKeys[0].Name = canarytail.RoleAuthor
	}

	if len(canary.Claim.PublicKeys) < canary.Claim.MinSigners {
		return fmt.Errorf(
			"total number of signers should be at least min signers, min_signers=%d, total=%d",
			canary.Claim.MinSigners, len(canary.Claim.PublicKeys),
		)
	}

	// sign it
	err = canary.Sign(privateSigningKey, publicSigningKey)
	if err != nil {
		return err
	}

	// and print it
	canaryFormatted := canary.Format()
	newFileName := canaryFileName(canary.Claim.Domain, canaryTime)
	latestFileName := canaryLatestFileName(canary.Claim.Domain)
	fp := path.Join(dir, newFileName)
	if err := writeToFile(fp, canaryFormatted); err != nil {
		return err
	}
	fp = path.Join(dir, latestFileName)
	if err := writeToFile(fp, canaryFormatted); err != nil {
		return err
	}

	absFp, err := filepath.Abs(fp)
	if err != nil {
		absFp = fp
	}
	fmt.Printf("Updated canary has been stored at %q\n", absFp)
	printNextSignerSuggestion(&canary)
	return nil
}

type canaryNewCmd struct {
	canaryOpCmd
}

func (cmd *canaryNewCmd) Run(ctx *context) error {
	// make sure the canary doesnt exist yet?
	// initialize the keys if they dont exist yet?
	return generateCanary(cmd.canaryOpCmd, readKeyPair)
}

type canaryUpdateCmd struct {
	canaryOpCmd
}

func (cmd *canaryUpdateCmd) Run(ctx *context) error {
	// make sure the canary already exists?
	return updateCanary(cmd.canaryOpCmd, readKeyPair)
}

type canaryPanicCmd struct {
	canaryOpCmd
}

func (cmd *canaryPanicCmd) Run(ctx *context) error {
	// make sure the canary doesnt exist yet?
	// initialize the keys if they dont exist yet?
	return updateCanary(cmd.canaryOpCmd, readPanicKeyPair)
}

type canaryPubkeyCmd struct {
	Domain string `arg name:"DOMAIN"`
}

func (cmd *canaryPubkeyCmd) Run(ctx *context) error {
	dir := canaryDirSafe(cmd.Domain)

	// read the key pair for this canary alias
	publickKey, err := readPublicKey(dir)
	if err != nil {
		fmt.Printf("Error when accessing public key for %q. Use 'key new %s' command to create a key if it does not exist.\n", cmd.Domain, cmd.Domain)
		return err
	}

	key := canarytail.FormatKey(publickKey)
	fmt.Printf("Your public key for %q is %q\n", cmd.Domain, key)
	return nil
}

type canaryValidateCmd struct {
	URI string `arg name:"uri"`
}

func (cmd *canaryValidateCmd) Run(ctx *context) error {
	// make sure the canary already exists?
	canary, err := canarytail.Read(cmd.URI)
	if err != nil {
		return err
	}

	fmt.Printf("Validating canary %v...\n", cmd.URI)

	if ok, err := canary.Validate(); !ok {
		return err
	}
	fmt.Println("OK!")
	return nil
}

type canarySignCmd struct {
	Path string `arg name:"canary_path"`
}

func (cmd *canarySignCmd) Run(ctx *context) error {
	canary, err := canarytail.ReadFile(cmd.Path)
	if err != nil {
		return err
	}
	dir := canaryDirSafe(canary.Claim.Domain)

	publicSigningKey, privateSigningKey, err := readKeyPair(dir)
	if err != nil {
		return err
	}

	// Check if signer exists in the list.
	exists := false
	pubKeyStr := canarytail.FormatKey(publicSigningKey)
	for _, pk := range canary.Claim.PublicKeys {
		if pk.Key == pubKeyStr {
			exists = true
			break
		}
	}
	if !exists {
		return fmt.Errorf("signer's public key not found in the list of signers")
	}

	fmt.Printf("Signing canary %v...\n", cmd.Path)

	err = canary.Sign(privateSigningKey, publicSigningKey)
	if err != nil {
		return err
	}

	canaryFormatted := canary.Format()
	if err := writeToFile(cmd.Path, canaryFormatted); err != nil {
		return err
	}

	printNextSignerSuggestion(&canary)
	return nil
}

type versionCmd struct {
}

func (cmd *versionCmd) Run(ctx *context) error {
	fmt.Printf("CLI Version %v\nStandard Version %v\n", version, canarytail.StandardVersion)
	return nil
}

// helpers

func canaryHomeDir() string {
	dir := os.Getenv("CANARY_HOME")
	if len(dir) == 0 {
		// get home folder
		home, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}

		return path.Join(home, ".canarytail")
	}
	return dir
}

func canaryDir(alias string) string {
	return path.Join(canaryHomeDir(), alias)
}

// returns the canary dir. if it doesnt exist, it gets created
func canaryDirSafe(alias string) string {
	homeDir := canaryHomeDir()
	if _, err := os.Stat(homeDir); os.IsNotExist(err) {
		os.Mkdir(homeDir, 0700)
	}
	dir := canaryDir(alias)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.Mkdir(dir, 0700)
	}
	return dir
}

func writeToFile(path, contents string) error {
	return ioutil.WriteFile(path, []byte(contents), 0600)
}

func readKeyPair(stagingPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, err := readPublicKey(stagingPath)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := readPrivateKey(stagingPath)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

func readPublicKey(stagingPath string) (ed25519.PublicKey, error) {
	publicKeyBytes, err := ioutil.ReadFile(path.Join(stagingPath, "public.b64"))
	if err != nil {
		return nil, err
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyBytes))
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func readPrivateKey(stagingPath string) (ed25519.PrivateKey, error) {
	privateKeyBytes, err := ioutil.ReadFile(path.Join(stagingPath, "private.b64"))
	if err != nil {
		return nil, err
	}

	privateKey, err := base64.StdEncoding.DecodeString(string(privateKeyBytes))
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func readPanicKeyPair(stagingPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKeyBytes, err := ioutil.ReadFile(path.Join(stagingPath, "panic-public.b64"))
	if err != nil {
		return nil, nil, err
	}

	privateKeyBytes, err := ioutil.ReadFile(path.Join(stagingPath, "panic-private.b64"))
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyBytes))
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := base64.StdEncoding.DecodeString(string(privateKeyBytes))
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

func readCanaryFile(path string) (canarytail.Canary, error) {
	canaryJSON, err := ioutil.ReadFile(path)
	if err != nil {
		return canarytail.Canary{}, err
	}

	var canary canarytail.Canary
	err = json.Unmarshal(canaryJSON, &canary)
	return canary, err
}

const (
	// canaryFileNameRegex matches strings like "canary.mydomain.com.1234567890.json"
	canaryFileNameRegex            = `canary\..+\.\d+\.json`
	canaryFileNameTimeCaptureRegex = `canary\..+\.(\d+)\.json`
)

var (
	ErrCanaryNotFound = errors.New("canary not found")
)

func canaryFileName(domain string, t time.Time) string {
	return fmt.Sprintf("canary.%s.%d.json", domain, t.UnixMilli())
}

func canaryLatestFileName(domain string) string {
	return fmt.Sprintf("canary.%s.latest.json", domain)
}

func getLatestCanaryFileName(dir string) (fname string, err error) {
	fnRegex, err := regexp.Compile(canaryFileNameRegex)
	if err != nil {
		return "", err
	}
	fnCaptureRegex, err := regexp.Compile(canaryFileNameTimeCaptureRegex)
	if err != nil {
		return "", err
	}

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return "", err
	}

	maxTs := -1
	for i := 0; i < len(files); i++ {
		if files[i].IsDir() {
			continue
		}
		if !fnRegex.MatchString(files[i].Name()) {
			continue
		}

		// If fnRegex matches, then fnCaptureRegex will always capture the timestamp.
		match := fnCaptureRegex.FindStringSubmatch(files[i].Name())
		ts, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}

		if ts > maxTs {
			maxTs = ts
			fname = files[i].Name()
		}
	}

	if fname == "" {
		return "", ErrCanaryNotFound
	}

	return fname, nil
}
