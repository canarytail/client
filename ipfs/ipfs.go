package ipfs

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	canarytail "github.com/canarytail/client"
	ipfs_shell "github.com/ipfs/go-ipfs-api"
)

const (
	canaryPrefix = "canary."
)

var (
	ErrNoIPNSKey      = errors.New("no ipns key hash found")
	ErrCanaryNotFound = errors.New("canary not found")
)

// StoreNewCanary fetching the existing canaries to disk from IPNS and stores
// the new canary along with existing canaries back to IPNS.
func StoreNewCanary(ipfsApiURL string, c *canarytail.Canary, t time.Time) error {
	if c.Claim.IPNSKey == nil || *c.Claim.IPNSKey == "" {
		return ErrNoIPNSKey
	}

	dir, err := FetchCanariesToDisk(ipfsApiURL, *c.Claim.IPNSKey, t)
	if err != nil {
		return err
	}

	return StoreCanaryInDir(ipfsApiURL, c, t, dir)
}

// FetchCanariesToDisk fetches the canaries from IPNS and stores them on local disk.
func FetchCanariesToDisk(ipfsApiURL, ipnsKey string, t time.Time) (dir string, err error) {
	if ipnsKey == "" {
		return "", ErrNoIPNSKey
	}

	fmt.Printf("Resolving IPNS key %s\n", ipnsKey)
	// Resolve ipns key and get the dir hash.
	sh := ipfs_shell.NewShell(ipfsApiURL)
	dirHash, err := sh.Resolve(ipnsKey)
	if err != nil {
		return "", err
	}
	fmt.Printf("IPNS key resolved to %s\n", dirHash)

	// Get all files from the IPFS dir to a local dir.
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir = path.Join(wd, fmt.Sprintf("%s%d", canaryPrefix, t.Unix()))
	fmt.Printf("Fetching existing canaries into %s\n", dir)
	if err := sh.Get(dirHash, dir); err != nil {
		return "", err
	}

	return dir, nil
}

// StoreCanaryInDir stores the new canary along with existing canaries in the directory back to IPNS.
func StoreCanaryInDir(ipfsApiURL string, c *canarytail.Canary, t time.Time, dir string) error {
	if c.Claim.IPNSKey == nil || *c.Claim.IPNSKey == "" {
		return ErrNoIPNSKey
	}

	// Place this new canary in the local dir.
	canaryFileName := fmt.Sprintf("canary.%d.json", t.Unix())
	fmt.Printf("Storing %s into %s\n", canaryFileName, dir)
	filePath := path.Join(dir, canaryFileName)
	if err := ioutil.WriteFile(filePath, []byte(c.Format()), os.ModePerm); err != nil {
		return err
	}

	fmt.Printf("Adding %s to IPFS\n", dir)
	sh := ipfs_shell.NewShell(ipfsApiURL)
	// Add this local dir to ipfs.
	newDirHash, err := sh.AddDir(dir)
	if err != nil {
		return err
	}
	fmt.Printf("New directory added to IPFS as /ipfs/%s\n", newDirHash)

	// Publish this IPFS dir to IPNS.
	fmt.Printf("Publishing /ipfs/%s, this may take a while\n", newDirHash)
	// TODO: how to specify the IPNS key here?
	// '/ipns/<ipns_key>' works here but gives error when resolving the IPNS key.
	// Passing "" takes the IPNS key from local IPFS info.
	return sh.Publish("", newDirHash)
}

// GetLatestCanary returns the file name of the latest canary in the directory.
func GetLatestCanary(dir string) (fname string, err error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return "", err
	}

	maxTs := -1
	for i := 0; i < len(files); i++ {
		if !strings.HasPrefix(files[i].Name(), canaryPrefix) {
			continue
		}
		if files[i].IsDir() {
			continue
		}
		ts, err := strconv.Atoi(strings.Split(files[i].Name(), ".")[1])
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
