package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
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
		New keyNewCmd `cmd help:"Generates a new key for signing canaries and saves to $CANARY_HOME/ALIAS"`
	} `cmd help:"This command is for manipulating cryptographic keys."`

	Canary struct {
		New      canaryNewCmd      `cmd help:"Generates a new canary, signs it using the key located in $CANARY_HOME/ALIAS, and saves to that same path. Codes provided in OPTIONS will be removed from the canary, signifying that event has triggered the canary."`
		Update   canaryUpdateCmd   `cmd help:"Updates the existing canary named ALIAS. If no OPTIONS are provided, it merely updates the signature date. If no EXPIRY is provided, it reuses the previous value	(e.g. renewing for a month). Codes provided in OPTIONS will be removed from the canary, signifying that event has triggered the canary."`
		Validate canaryValidateCmd `cmd help:"Validates a canary's signature"`
	} `cmd help:"This command is for manipulating canaries."`

	Version versionCmd `cmd help:"Show version and exit"`
}

func main() {
	ctx := kong.Parse(&cli)
	err := ctx.Run(&context{Debug: cli.Debug})
	ctx.FatalIfErrorf(err)
}

type initCmd struct {
}

type keyCmd struct {
	New keyNewCmd `cmd help:"Generates a new key for signing canaries and saves to $CANARY_HOME/ALIAS"`
}

type keyNewCmd struct {
	Alias string `arg name:"alias" help:"Alias of the canary"`
}

func (cmd *keyNewCmd) Run(ctx *context) error {
	stagingPath := canaryDirSafe(cmd.Alias)

	fmt.Printf("Generating keypair for %v at %v...\n", cmd.Alias, stagingPath)
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

	return nil
}

type canaryOpCmd struct {
	Alias string `arg name:"alias"`

	Expiry int  `name:"expiry" help:"Expires in # minutes from now (default: 43200, one month)" default:"43200"`
	GAG    bool `name:"GAG" help:"Gag order received"`
	TRAP   bool `name:"TRAP" help:"Trap and trace order received"`
	DURESS bool `name:"DURESS" help:"Under duress (coercion, blackmail, etc)"`
	XCRED  bool `name:"XCRED" help:"Compromised credentials"`
	XOPERS bool `name:"XOPERS" help:"Operations compromised"`
	WAR    bool `name:"WAR" help:"Warrant received"`
	SUBP   bool `name:"SUBP" help:"Subpoena received"`
	CEASE  bool `name:"CEASE" help:"Court order to cease operations"`
	RAID   bool `name:"RAID" help:"Raided, but data unlikely compromised"`
	SEIZE  bool `name:"SEIZE" help:"Hardware or data seized, unlikely compromised"`
}

func getCodes(cmd canaryOpCmd) []string {
	codes := make([]string, 0)
	if cmd.GAG {
		codes = append(codes, "GAG")
	}
	if cmd.TRAP {
		codes = append(codes, "TRAP")
	}
	if cmd.DURESS {
		codes = append(codes, "DURESS")
	}
	if cmd.XCRED {
		codes = append(codes, "XCRED")
	}
	if cmd.XOPERS {
		codes = append(codes, "XOPERS")
	}
	if cmd.WAR {
		codes = append(codes, "WAR")
	}
	if cmd.SUBP {
		codes = append(codes, "SUBP")
	}
	if cmd.CEASE {
		codes = append(codes, "CEASE")
	}
	if cmd.RAID {
		codes = append(codes, "RAID")
	}
	if cmd.SEIZE {
		codes = append(codes, "SEIZE")
	}
	return canarytail.InverseCodes(codes)
}

func generateCanary(cmd canaryOpCmd) error {
	dir := canaryDirSafe(cmd.Alias)

	// read the key pair for this canary alias
	publickKey, privateKey, err := readKeyPair(dir)
	if err != nil {
		return err
	}

	// form the canary
	canary := &canarytail.Canary{Claim: canarytail.CanaryClaim{
		Domain:    cmd.Alias,
		Codes:     getCodes(cmd),
		Release:   time.Now().Format(canarytail.TimestampLayout),
		Freshness: canarytail.GetLastBlockChainBlockHashFormatted(),
		Expiry:    time.Now().Add(time.Duration(cmd.Expiry) * time.Minute).Format(canarytail.TimestampLayout),
		Version:   canarytail.StandardVersion,
		PubKey:    canarytail.FormatKey(publickKey),
	}}

	// sign it
	err = canary.Sign(privateKey)
	if err != nil {
		return err
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
	generateCanary(cmd.canaryOpCmd)
	return nil
}

type canaryUpdateCmd struct {
	canaryOpCmd
}

func (cmd *canaryUpdateCmd) Run(ctx *context) error {
	// make sure the canary already exists?
	generateCanary(cmd.canaryOpCmd)
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

	if !canary.Validate() {
		return fmt.Errorf("The canary is not valid")
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

func readCanaryFile(path string) (canarytail.Canary, error) {
	canaryJSON, err := ioutil.ReadFile(path)
	if err != nil {
		return canarytail.Canary{}, err
	}

	var canary canarytail.Canary
	err = json.Unmarshal(canaryJSON, &canary)
	return canary, err
}
