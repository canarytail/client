package canarytail_test

import (
	"encoding/hex"
	"testing"

	"github.com/jirojo2/canarytail"
	"github.com/stretchr/testify/assert"
)

func TestGetLastBlockChainBlockHash(t *testing.T) {
	block := canarytail.GetLastBlockChainBlockHash()
	assert.Len(t, block, 32)
}

func TestGetBlockInfo(t *testing.T) {
	blockStr := "0000000000000000000a6e5fe805308bdc3656e650bb7937888d787d2d520b4c"
	blockHex, _ := hex.DecodeString(blockStr)
	block, err := canarytail.GetBlockInfo(blockHex)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, blockStr, block.Hash)
}
