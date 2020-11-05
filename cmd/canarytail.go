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

	"github.com/mitchellh/go-homedir"
)

type context struct {
	Debug bool
}

type generateKeyPairCmd struct {
}

func (cmd *generateKeyPairCmd) Run(ctx *context) error {
	fmt.Println("Generating keypair...")
	defer fmt.Println("Done.")
	return generateKeyPair()
}

type signCmd struct {
	Domain string   `arg name:"domain" help:"Domain for this canary. Example: google.com."`
	Codes  []string `arg optional name:"code" help:"Codes to flag. If a code is flagged, the canary will trigger. If everything is good, no codes should be flagged."`
}

func (cmd *signCmd) Run(ctx *context) error {
	publickKey, _, err := readKeyPair()
	if err != nil {
		return err
	}

	canary, err := sign(canarytail.CanaryClaim{
		Domain:    cmd.Domain,
		Codes:     canarytail.InverseCodes(cmd.Codes),
		Release:   time.Now().Format(canarytail.TimestampLayout),
		Freshness: canarytail.GetLastBlockChainBlockHashFormatted(),
		Expire:    time.Now().AddDate(10, 0, 0).Format(canarytail.TimestampLayout),
		Version:   canarytail.StandardVersion,
		PubKey:    canarytail.FormatKey(publickKey),
	})
	if err != nil {
		return err
	}

	fmt.Println(canary.Format())
	return nil
}

type validateCmd struct {
	CanaryPath string `arg name:"canary" help:"Path to a canary JSON file." type:"path"`
}

func (cmd *validateCmd) Run(ctx *context) error {
	canary, err := readCanaryFile(cmd.CanaryPath)
	if err != nil {
		return err
	}

	if !canary.Validate() {
		return fmt.Errorf("The canary is not valid")
	}
	fmt.Println("Ok!")
	return nil
}

var cli struct {
	Debug           bool               `help:"Enable debug mode."`
	GenerateKeyPair generateKeyPairCmd `cmd help:"Generates a new key pair."`
	Sign            signCmd            `cmd help:"Signs a canary with the provided arguments."`
	Validate        validateCmd        `cmd help:"Validates a canary JSON file."`
}

func main() {
	setupStagingDir()

	ctx := kong.Parse(&cli)
	err := ctx.Run(&context{Debug: cli.Debug})
	ctx.FatalIfErrorf(err)
}

func stagingDirPath() string {
	homePath, err := homedir.Dir()
	if err != nil {
		panic(fmt.Errorf("Could not get the home dir: %v", err))
	}
	return path.Join(homePath, ".canarytail")
}

func setupStagingDir() {
	stagingPath := stagingDirPath()

	if _, err := os.Stat(stagingPath); os.IsNotExist(err) {
		os.Mkdir(stagingPath, 0700)
	}
}

func writeToFile(path, contents string) error {
	return ioutil.WriteFile(path, []byte(contents), 0700)
}

func generateKeyPair() error {
	stagingPath := stagingDirPath()

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

func readKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	stagingPath := stagingDirPath()

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

func sign(claims canarytail.CanaryClaim) (canarytail.Canary, error) {
	_, privateKey, err := readKeyPair()
	if err != nil {
		panic(fmt.Errorf("Could not read the key pair: %v", err))
	}

	signatureRaw := canarytail.Sign(claims, privateKey)
	signatureEncoded := base64.StdEncoding.EncodeToString(signatureRaw)
	return canarytail.Canary{
		Claim:     claims,
		Signature: canarytail.CanarySignature(signatureEncoded),
	}, nil
}
