package main

import (
	"io/fs"
	"io/ioutil"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCanaryFileName(t *testing.T) {
	require.Equal(t, "canary.mydomain.com.100000000.json", canaryFileName("mydomain.com", time.Unix(100000, 0)))
	require.Equal(t, "canary.mydomain.com.12345678.json", canaryFileName("mydomain.com", time.Unix(12345, 678900000)))
}

func TestGetLatestCanaryFileName(t *testing.T) {
	t.Run("no valid canary", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, ioutil.WriteFile(path.Join(dir, "temp1.json"), []byte{1}, fs.ModePerm))
		require.NoError(t, ioutil.WriteFile(path.Join(dir, "temp2.json"), []byte{1}, fs.ModePerm))
		_, err := getLatestCanaryFileName(dir)
		require.Equal(t, ErrCanaryNotFound, err)
	})
	t.Run("valid canary with invalid files", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, ioutil.WriteFile(path.Join(dir, "temp1.json"), []byte{1}, fs.ModePerm))
		require.NoError(t, ioutil.WriteFile(path.Join(dir, "temp2.json"), []byte{1}, fs.ModePerm))
		for _, unixTime := range []int64{1000, 3000, 5000, 9000} {
			fn := canaryFileName("canarytail.org", time.Unix(unixTime, 0))
			require.NoError(t, ioutil.WriteFile(path.Join(dir, fn), []byte{1}, fs.ModePerm))
		}

		exp := canaryFileName("canarytail.org", time.Unix(9000, 0))
		act, err := getLatestCanaryFileName(dir)
		require.NoError(t, err)
		require.Equal(t, exp, act)
	})
}
