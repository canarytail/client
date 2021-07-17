package ipfs

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	canarytail "github.com/canarytail/client"
	ipfs_shell "github.com/ipfs/go-ipfs-api"
)

var (
	ErrNoIPNSKey = errors.New("no ipns key hash found")
)

func StoreCanary(ipfsApiURL string, c *canarytail.Canary, releaseTime time.Time) error {
	if c.Claim.IPNSKey == nil || *c.Claim.IPNSKey == "" {
		return ErrNoIPNSKey
	}

	fmt.Printf("Resolving IPNS key %s\n", *c.Claim.IPNSKey)
	// 1. Resolve ipns key and get the dir hash
	sh := ipfs_shell.NewShell(ipfsApiURL)
	dirHash, err := sh.Resolve(*c.Claim.IPNSKey)
	if err != nil {
		return err
	}
	fmt.Printf("IPNS key resolved to %s\n", dirHash)

	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	dir := path.Join(wd, fmt.Sprintf("canary.%d", releaseTime.Unix()))

	fmt.Printf("Fetching existing canaries and storing new one in %s\n", dir)

	// 2. Get all files from the dir
	if err := sh.Get(dirHash, dir); err != nil {
		return err
	}

	// 3. Place this canary in dir
	canaryFileName := fmt.Sprintf("canary.%d.json", releaseTime.Unix())
	filePath := path.Join(dir, canaryFileName)
	if err := ioutil.WriteFile(filePath, []byte(c.Format()), os.ModePerm); err != nil {
		return err
	}

	// 4. Add this dir to ipfs
	newDirHash, err := sh.AddDir(dir)
	if err != nil {
		return err
	}
	fmt.Printf("New directory added to IPFS as /ipfs/%s\n", newDirHash)

	// 5. Publish this dir to IPNS
	fmt.Printf("Publishing /ipfs/%s, this may take a while\n", newDirHash)
	// TODO: how to specify the IPNS key here?
	// '/ipns/<ipns_key>' works here but gives error when resolving the IPNS key.
	// Passing "" takes the IPNS key from local IPFS info.
	return sh.Publish("", newDirHash)
}
