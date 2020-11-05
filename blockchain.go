package canarytail

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// Blockchain
// https://www.blockchain.com/api/blockchain_api => doc for the Data API
// https://blockchain.info/q/latesthash => Get latest block hash
// https://blockchain.info/rawblock/0000000000000bae09a7a393a8acded75aa67e46cb81f7acaa5ad94f9eacd103 => Get block info

func readBlockChainAPI(url string) (content []byte, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("Could not retrieve canary, got code %v", resp.StatusCode)
		return
	}

	return ioutil.ReadAll(resp.Body)
}

// BlockInfo represents a block in the BlockChain Data API
// https://www.blockchain.com/api/blockchain_api
//
// {
//     "hash":"0000000000000bae09a7a393a8acded75aa67e46cb81f7acaa5ad94f9eacd103",
//     "ver":1,
//     "prev_block":"00000000000007d0f98d9edca880a6c124e25095712df8952e0439ac7409738a",
//     "mrkl_root":"935aa0ed2e29a4b81e0c995c39e06995ecce7ddbebb26ed32d550a72e8200bf5",
//     "time":1322131230,
//     "bits":437129626,
//     "nonce":2964215930,
//     "n_tx":22,
//     "size":9195,
//     "block_index":818044,
//     "main_chain":true,
//     "height":154595,
//     "received_time":1322131301,
//     "relayed_by":"108.60.208.156",
//     "tx":[--Array of Transactions--]
// }
type BlockInfo struct {
	Hash          string `json:"hash"`
	PreviousBlock string `json:"prev_block"`
	Time          int64  `json:"time"`
	Bits          int64  `json:"bits"`
	BlockIndex    int    `json:"block_index"`
	Height        int    `json:"height"`
}

// GetLastBlockChainBlockHash retrieves the latest block hash from the BlockChain Data API
func GetLastBlockChainBlockHash() []byte {
	content, err := readBlockChainAPI("https://blockchain.info/q/latesthash")
	hash, err := hex.DecodeString(string(content))
	if err != nil {
		return nil
	}
	return hash
}

// FormatBlockChainBlockHash formats a block hash in the standartd string format
func FormatBlockChainBlockHash(blockHash []byte) string {
	return hex.EncodeToString(blockHash)
}

// GetLastBlockChainBlockHashFormatted retrieves the latest block hash from the BlockChain Data API, in the standard string format
func GetLastBlockChainBlockHashFormatted() string {
	return FormatBlockChainBlockHash(GetLastBlockChainBlockHash())
}

// GetBlockInfo retrieves the block information from the BlockChain Data API
func GetBlockInfo(blockHash []byte) (BlockInfo, error) {
	url := fmt.Sprintf("https://blockchain.info/rawblock/%s", hex.EncodeToString(blockHash))
	content, err := readBlockChainAPI(url)
	if err != nil {
		return BlockInfo{}, err
	}

	var blockInfo BlockInfo
	err = json.Unmarshal(content, &blockInfo)
	return blockInfo, err
}
