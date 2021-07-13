package ipfs

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	canarytail "github.com/canarytail/client"
	ipfs_shell "github.com/ipfs/go-ipfs-api"
)

func dummy() {
	// Where your local node is running on localhost:5001
	sh := ipfs_shell.NewShell("localhost:5001")
	cid, err := sh.Add(strings.NewReader("hello world!"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s", err)
		os.Exit(1)
	}
	fmt.Printf("added %s", cid)
}

var (
	ErrNoDirHash = errors.New("no ipfs directory hash found")
)

func StoreCanary(ipfsApiURL string, c *canarytail.Canary, releaseTime time.Time) error {
	if c.Claim.IPNSKey == nil || *c.Claim.IPNSKey == "" {
		return ErrNoDirHash
	}

	// 1. Resolve ipns key and get the dir hash
	// 2. Get all files from the dir
	// 3. Place this canary in dir
	// 4. Add this dir to ipfs
	// 5. Publish this dir to IPNS

	//sh := ipfs_shell.NewShell(ipfsApiURL)
	//filename := fmt.Sprintf("%s.%d.json", c.Claim.Domain, releaseTime.Unix())

	return nil
}
