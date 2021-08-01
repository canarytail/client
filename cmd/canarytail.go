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
	"time"

	"github.com/alecthomas/kong"
	canarytail "github.com/canarytail/client"
	"github.com/canarytail/client/ipfs"
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

	Expiry  int    `name:"expiry" help:"Expires in # minutes from now (default: 43200, one month)" default:"43200"`
	GAG     bool   `name:"GAG" help:"Gag order received"`
	TRAP    bool   `name:"TRAP" help:"Trap and trace order received"`
	DURESS  bool   `name:"DURESS" help:"Under duress (coercion, blackmail, etc)"`
	XCRED   bool   `name:"XCRED" help:"Compromised credentials"`
	XOPERS  bool   `name:"XOPERS" help:"Operations compromised"`
	WAR     bool   `name:"WAR" help:"Warrant received"`
	SUBP    bool   `name:"SUBP" help:"Subpoena received"`
	CEASE   bool   `name:"CEASE" help:"Court order to cease operations"`
	RAID    bool   `name:"RAID" help:"Raided, but data unlikely compromised"`
	SEIZE   bool   `name:"SEIZE" help:"Hardware or data seized, unlikely compromised"`
	IPNSKey string `name:"ipns_key" help:"IPNS key where existing canaries are stored and new ones should be stored"`
	IPFSURL string `name:"ipfs_url" help:"IPFS API URL to perform read/write operations"`
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

	// compose the canary
	releaseTime := time.Now()
	canary := &canarytail.Canary{Claim: canarytail.CanaryClaim{
		Domain:     cmd.Domain,
		Codes:      getCodes(cmd),
		Release:    releaseTime.Format(canarytail.TimestampLayout),
		Freshness:  canarytail.GetLastBlockChainBlockHashFormatted(),
		Expiry:     releaseTime.Add(time.Duration(cmd.Expiry) * time.Minute).Format(canarytail.TimestampLayout),
		Version:    canarytail.StandardVersion,
		PublicKeys: []string{canarytail.FormatKey(publickKey)},
		PanicKey:   canarytail.FormatKey(publicPanicKey),
	}}

	h := cmd.IPNSKey
	if h != "" {
		canary.Claim.IPNSKey = &h
	}

	// sign it
	err = canary.Sign(privateSigningKey, publicSigningKey)
	if err != nil {
		return err
	}

	if canary.Claim.IPNSKey != nil && cmd.IPFSURL != "" {
		if err := ipfs.StoreNewCanary(cmd.IPFSURL, canary, releaseTime); err != nil {
			return fmt.Errorf("failed to write canary to IPFS: %s", err.Error())
		}
	}

	// and print it
	canaryFormatted := canary.Format()
	writeToFile(path.Join(dir, "canary.json"), canaryFormatted)
	fmt.Println(canaryFormatted)
	return nil
}

func updateCanary(cmd canaryOpCmd, signingKeyPairReader keyPairReader) error {
	var (
		dir        = canaryDirSafe(cmd.Domain)
		fpath      = path.Join(dir, "canary.json")
		updateTime = time.Now()
		ipfsCanDir string
	)

	var canary canarytail.Canary
	if cmd.IPFSURL != "" && cmd.IPNSKey != "" {
		// IPNS info given. Get the canary from IPNS.
		var err error
		ipfsCanDir, err = ipfs.FetchCanariesToDisk(cmd.IPFSURL, cmd.IPNSKey, updateTime)
		if err != nil {
			return err
		}

		fname, err := ipfs.GetLatestCanary(ipfsCanDir)
		if err != nil {
			return err
		}

		fmt.Printf("Using the latest canary %s for the update\n", fname)

		fpath = path.Join(ipfsCanDir, fname)
	}

	canary, err := readCanaryFile(fpath)
	if err != nil {
		return err
	}
	if canary.Claim.IPNSKey != nil && *canary.Claim.IPNSKey != "" {
		if cmd.IPNSKey != *canary.Claim.IPNSKey {
			return fmt.Errorf("mismatch in IPNS keys, CLI key=%s, canary key=%s", cmd.IPNSKey, *canary.Claim.IPNSKey)
		}
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

	// update the canary
	canary.Claim.Release = updateTime.Format(canarytail.TimestampLayout)
	canary.Claim.Freshness = canarytail.GetLastBlockChainBlockHashFormatted()
	canary.Claim.Expiry = updateTime.Add(time.Duration(cmd.Expiry) * time.Minute).Format(canarytail.TimestampLayout)
	canary.Claim.Version = canarytail.StandardVersion
	canary.Claim.Codes = getCodes(cmd)

	// if the public key is not there, add it
	publicKeyEnc := canarytail.FormatKey(publicSigningKey)
	if publicKeyEnc != canary.Claim.PanicKey {
		foundPubKey := false
		for _, x := range canary.Claim.PublicKeys {
			if x == publicKeyEnc {
				foundPubKey = true
				break
			}
		}
		if !foundPubKey {
			canary.Claim.PublicKeys = append(canary.Claim.PublicKeys, publicKeyEnc)
		}
	}

	// if the panic key is not the same, error out
	panicKeyEnc := canarytail.FormatKey(publicPanicKey)
	if panicKeyEnc == publicKeyEnc && panicKeyEnc != canary.Claim.PanicKey {
		return errors.New("The panic key does not match")
	}

	// sign it
	err = canary.Sign(privateSigningKey, publicSigningKey)
	if err != nil {
		return err
	}

	if canary.Claim.IPNSKey != nil && cmd.IPFSURL != "" {
		if err := ipfs.StoreCanaryInDir(cmd.IPFSURL, &canary, updateTime, ipfsCanDir); err != nil {
			return fmt.Errorf("failed to write canary to IPFS: %s", err.Error())
		}
	}

	// and print it
	canaryFormatted := canary.Format()
	writeToFile(path.Join(dir, "canary.json"), canaryFormatted)
	fmt.Println(canaryFormatted)
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
	publicKeyBytes, err := ioutil.ReadFile(path.Join(stagingPath, "public.b64"))
	if err != nil {
		return nil, nil, err
	}

	privateKeyBytes, err := ioutil.ReadFile(path.Join(stagingPath, "private.b64"))
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
