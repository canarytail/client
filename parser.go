package canarytail

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// Read parses a canary from a URL or a local path
func Read(url string) (Canary, error) {
	if isHTTP(url) {
		return readHTTP(url)
	}
	return readFile(url)
}

// ReadFile parses a canary from a local path
func ReadFile(path string) (Canary, error) {
	return readFile(path)
}

func isHTTP(url string) bool {
	return strings.HasPrefix(strings.ToLower(url), "http")
}

func readFile(path string) (canary Canary, err error) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	contents, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}

	return readBytes(contents)
}

func readHTTP(url string) (canary Canary, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("Could not retrieve canary, got code %v", resp.StatusCode)
		return
	}

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	return readBytes(contents)
}

func readBytes(contents []byte) (canary Canary, err error) {
	err = json.Unmarshal(contents, &canary)
	return
}
