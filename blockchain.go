package canarytail

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"time"
)

func BitcoinReadBlockChainAPI(url string) (content []byte, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("Could not get blockchain info, got code %v", resp.StatusCode)
		return
	}

	return ioutil.ReadAll(resp.Body)
}

// Blockchain
// https://www.blockchain.com/api/blockchain_api => doc for the Data API
// https://blockchain.info/q/latesthash => Get latest block hash
// https://blockchain.info/rawblock/0000000000000bae09a7a393a8acded75aa67e46cb81f7acaa5ad94f9eacd103 => Get block info

func readBlockChainAPI(url string, postData []byte) (content []byte, err error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(postData))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("Could not get blockchain info, got code %v", resp.StatusCode)
		return
	}

	return ioutil.ReadAll(resp.Body)
}

// BitcoinBlockInfo represents a block in the BlockChain Data API
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
type BitcoinBlockInfo struct {
	Hash          string `json:"hash"`
	PreviousBlock string `json:"prev_block"`
	Time          int64  `json:"time"`
	Bits          int64  `json:"bits"`
	BlockIndex    int    `json:"block_index"`
	Height        int    `json:"height"`
}

type MoneroFailMoneroNodeList struct {
	ClearNodes []string `json:"clear"`
}

type MoneroFailResult struct {
	AllNodes MoneroFailMoneroNodeList `json:"monero"`
}

func getRandomMoneroNode() string {
	resp, err := http.Get("https://monero.fail/nodes.json")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("Could not retrieve canary, got code %v", resp.StatusCode)
		return ""
	}

	resString, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	var moneroFail MoneroFailResult
	derr := json.Unmarshal(resString, &moneroFail)

	if derr != nil {
		return ""
	}

	rand.Seed(time.Now().Unix())
	chosenNode := moneroFail.AllNodes.ClearNodes[rand.Intn(len(moneroFail.AllNodes.ClearNodes))]
	fmt.Println("No Monero Node specified, choosing at random:", chosenNode)

	return chosenNode
}

type MoneroGetInfoResult struct {
	Hash   string `json:"top_block_hash"`
	Height int    `json:"height"`
}

type MoneroGetInfo struct {
	Id            string              `json:"id"`
	GetInfoResult MoneroGetInfoResult `json:"result"`
}

type MoneroBlockHeader struct {
	Hash          string `json:"hash"`
	PreviousBlock string `json:"prev_hash"`
	Height        int    `json:"height"`
	Time          int64  `json:"timestamp"`
}

type MoneroGetBlockHeaderByHashResult struct {
	BlockHeader MoneroBlockHeader `json:"block_header"`
}

type MoneroGetBlockHeaderByHash struct {
	GetBlockHeaderByHashResult MoneroGetBlockHeaderByHashResult `json:"result"`
}

// GetLastBlockChainBlockHash retrieves the latest block hash from the BlockChain Data API
func GetLastBlockChainBlockHash(moneroNode string) []byte {
	body := []byte(`{
		"jsonrpc": "2.0",
		"id":      "0",
		"method":  "get_info",
		"params":  {}
	}`)

	if moneroNode == "" {
		moneroNode = getRandomMoneroNode()
	}

	content, err := readBlockChainAPI(moneroNode + "/json_rpc", body)

	if err != nil {
		return nil
	}

	var getInfo MoneroGetInfo
	derr := json.Unmarshal(content, &getInfo)

	if derr != nil {
		return nil
	}

	hash, err := hex.DecodeString(string(getInfo.GetInfoResult.Hash))

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
func GetLastBlockChainBlockHashFormatted(moneroNode string) string {
	return FormatBlockChainBlockHash(GetLastBlockChainBlockHash(moneroNode))
}

// GetBlockInfo retrieves the block information from the BlockChain Data API
func GetBlockInfo(moneroNode string, blockHash []byte) (MoneroGetBlockHeaderByHash, error) {
	bodyStr := fmt.Sprintf(`{
		"jsonrpc": "2.0",
		"id":      "0",
		"method":  "get_block_header_by_hash",
		"params":  {
			"hash": "%v"
		}
	}`, FormatBlockChainBlockHash(blockHash))

	body := []byte(bodyStr)

	if moneroNode == "" {
		moneroNode = getRandomMoneroNode()
	}

	content, err := readBlockChainAPI(moneroNode + "/json_rpc", body)

	if err != nil {
		fmt.Println(err)
		return MoneroGetBlockHeaderByHash{}, err
	}

	var getBlockInfo MoneroGetBlockHeaderByHash
	derr := json.Unmarshal(content, &getBlockInfo)

	if derr != nil {
		fmt.Println(err)
		return MoneroGetBlockHeaderByHash{}, err
	}

	return getBlockInfo, nil
}

func BitcoinGetBlockInfo(blockHash []byte) (BitcoinBlockInfo, error) {
	url := fmt.Sprintf("https://blockchain.info/rawblock/%s", hex.EncodeToString(blockHash))
	content, err := BitcoinReadBlockChainAPI(url)
	if err != nil {
		return BitcoinBlockInfo{}, err
	}

	var blockInfo BitcoinBlockInfo
	err = json.Unmarshal(content, &blockInfo)

	return blockInfo, err
}

func GetBlockTimeByHash(blockHash []byte, moneroNode string, useBitcoin bool) (Timestamp int64) {
	var blockReleasedTime int64
	// this is here for legacy support. all new canaries will use the monero chain
	if useBitcoin == true {
		blockInfo, err := BitcoinGetBlockInfo(blockHash)
		if err != nil {
			fmt.Errorf("Could not validate the canary: the block provided seems not to be valid, or there is an issue retrieving the block info: %v", err)
			return 0
		}

		blockReleasedTime = blockInfo.Time
	} else {
		blockInfo, err := GetBlockInfo(moneroNode, blockHash)
		if err != nil {
			fmt.Errorf("Could not validate the canary: the block provided seems not to be valid, or there is an issue retrieving the block info: %v", err)
			return 0
		}

		blockReleasedTime = blockInfo.GetBlockHeaderByHashResult.BlockHeader.Time
	}

	return blockReleasedTime
}
