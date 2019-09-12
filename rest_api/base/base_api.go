package baseapi

import (
	"bytes"
	"errors"

	"github.com/aeternity/aepp-sdk-go/aeternity"
	"github.com/aeternity/aepp-sdk-go/utils"

	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	postgre "aepp-token-migration-backend/postgre_sql"
	types "aepp-token-migration-backend/types"
	appUtils "aepp-token-migration-backend/utils"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

var backend = "fate" // aeternity.Config.Compiler.Backend
var abiVersion uint16 = 3 // aeternity.Config.Client.Contracts.ABIVersion // aevm = 1 || fate = 3
// var vmVersion uint16 = 5 // aeternity.Config.Client.Contracts.VMVersion // fate = 5


var userToken string = "89B28858-5FFA-0E4C-FF73-480646005600"
var migrationsCount int

// MerkleTreeStatus takes pointer to initialized router and the merkle tree and exposes Rest API routes for getting of status
func MerkleTreeStatus(treeRouter chi.Router, tree types.ExternalMerkleTree) chi.Router {
	treeRouter.Get("/", getTreeStatus(tree))
	return treeRouter
}

// MerkleTreeHashes takes pointer to initialized router and the merkle tree and exposes Rest API routes for getting of intermediary hashes
func MerkleTreeHashes(treeRouter chi.Router, tree types.ExternalMerkleTree) chi.Router {
	treeRouter.Get("/siblings/{index}", getIntermediaryHashesHandler(tree))
	return treeRouter
}

// MerkleAPIResponse represents the minimal response structure
type MerkleAPIResponse struct {
	Status bool   `json:"status"`
	Error  string `json:"error,omitempty"`
}

type treeStatusResponse struct {
	MerkleAPIResponse
	Tree types.MerkleTree `json:"tree"`
}

func getTreeStatus(tree types.ExternalMerkleTree) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		appUtils.LogRequest(r, "get /")

		if tree.Length() == 0 {
			render.JSON(w, r, treeStatusResponse{MerkleAPIResponse{true, ""}, nil})
			return
		}
		render.JSON(w, r, treeStatusResponse{MerkleAPIResponse{true, ""}, tree})
		return
	}
}

type intermediaryHashesResponse struct {
	MerkleAPIResponse
	Hashes []string `json:"hashes"`
}

func getIntermediaryHashesHandler(tree types.ExternalMerkleTree) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appUtils.LogRequest(r, "/siblings/{index}")

		index, err := strconv.Atoi(chi.URLParam(r, "index"))
		if err != nil {
			render.JSON(w, r, intermediaryHashesResponse{MerkleAPIResponse{false, err.Error()}, nil})
			return
		}
		hashes, err := tree.IntermediaryHashesByIndex(index)
		if err != nil {
			render.JSON(w, r, intermediaryHashesResponse{MerkleAPIResponse{false, err.Error()}, nil})
			return
		}
		render.JSON(w, r, intermediaryHashesResponse{MerkleAPIResponse{true, ""}, hashes})
	}
}

type addDataRequest struct {
	Data string `json:"data"`
}

type addDataResponse struct {
	MerkleAPIResponse
	Index int    `json:"index"`
	Hash  string `json:"hash,omitempty"`
}

// GetHashByLeafIndex gets hash at index 'X'
func GetHashByLeafIndex(router chi.Router, tree *postgre.PostgresMerkleTree) chi.Router {

	router.Get("/hash/{index}", getHashByLeafIndex(tree))

	return router
}

func getHashByLeafIndex(tree *postgre.PostgresMerkleTree) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		appUtils.LogRequest(req, "/hash/{index}")

		type hashResponse struct {
			Index int    `json:"index"`
			Hash  string `json:"hash"`
		}

		indexAsStr := chi.URLParam(req, "index")
		index, err := strconv.Atoi(indexAsStr)
		if err != nil {
			log.Printf("[ERROR] Invalid query param. Index should be an integer. %s", err)
			http.Error(w, "Invalid query param. Index should be an integer.", 400)
			return
		}

		hashAtIndex, err := tree.HashAt(index)
		if err != nil {
			log.Printf("[ERROR] get hash at index. %s", err)
			http.Error(w, "Invalid index.", 400)
			return
		}

		render.JSON(w, req, hashResponse{Index: index, Hash: hashAtIndex})
	}
}

// GetInfoByEthAddress gets additional info like hash, index, number of tokens by eth address
func GetInfoByEthAddress(router chi.Router, tree *postgre.PostgresMerkleTree) chi.Router {

	router.Get("/info/{ethAddress}", getInfoByEthAddress(tree))

	return router
}

func getInfoByEthAddress(tree *postgre.PostgresMerkleTree) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		type hashResponse struct {
			Index         int    `json:"index"`
			Hash          string `json:"hash"`
			Tokens        string `json:"tokens"`
			Migrated      bool   `json:"migrated"`
			MigrateTxHash string `json:"migrateTxHash"`
		}

		ethAddress := chi.URLParam(req, "ethAddress")
		if ethAddress == "" {
			appUtils.LogRequest(req, fmt.Sprintf("/info/%s", "missing_eth_address"))
			http.Error(w, "Invalid request! Missing eth address!", 400)
			return
		}

		appUtils.LogRequest(req, fmt.Sprintf("/info/%s", ethAddress))

		migrationInfo := tree.GetByEthAddress(strings.ToLower(ethAddress))

		render.JSON(w, req, hashResponse{Index: migrationInfo.Leaf_index, Hash: migrationInfo.Hash, Tokens: migrationInfo.Balance, Migrated: migrationInfo.Migrated == 1, MigrateTxHash: migrationInfo.Migrate_tx_hash})
	}
}

func Migrate(router chi.Router, tree *postgre.PostgresMerkleTree, secretKey string, contractSource string, aeContractAddress string, aeNodeUrl string) chi.Router {

	router.Post("/migrate", migrate(tree, secretKey, contractSource, aeContractAddress, aeNodeUrl))

	return router
}

func migrate(tree *postgre.PostgresMerkleTree, secretKey string, contractSource string, aeContractAddress string, aeNodeUrl string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		appUtils.LogRequest(req, "/migrate")
		
		type reqData struct {
			EthPubKey     string `json:"ethPubKey"`
			MessageDigest string `json:"messageDigest"`
			Signature     string `json:"signature"`
			AeAddress     string `json:"aeAddress"`
		}

		decoder := json.NewDecoder(req.Body)
		var data reqData
		err := decoder.Decode(&data)
		if err != nil {
			fmt.Printf("[ERROR] Cannot parse request body! %s\n", err)
			http.Error(w, "Cannot parse request body!", 400)
			return
		}

		if data.EthPubKey == "" {
			log.Printf("[ERROR] Missing EthPubKey! Migrate procedure should NOT start!\n")
			http.Error(w, "Missing EthPubKey! Migrate procedure should NOT start!", 400)
			return
		}

		if data.MessageDigest == "" {
			log.Printf("[ERROR] Missing MessageDigest! Migrate procedure should NOT start!\n")
			http.Error(w, "Missing MessageDigest! Migrate procedure should NOT start!", 400)
			return
		}

		if data.Signature == "" {
			log.Printf("[ERROR] Missing Signature! Migrate procedure should NOT start!\n")
			http.Error(w, "Missing Signature! Migrate procedure should NOT start!", 400)
			return
		}

		if data.AeAddress == "" {
			log.Printf("[ERROR] Missing AE address! Migrate procedure should NOT start!\n")
			http.Error(w, "Missing AE address! Migrate procedure should NOT start!", 400)
			return
		}

		// get additional data from db
		migrationInfo := tree.GetByEthAddress(data.EthPubKey)

		if migrationInfo.Migrated == 1 {
			log.Println("[ERROR] Eth [", data.EthPubKey, "] address already migrate its tokens!")
			http.Error(w, "Eth address already migrate its tokens!", 400)
			return
		}

		siblings, err := tree.IntermediaryHashesByIndex(migrationInfo.Leaf_index)
		if err != nil {
			log.Printf("[ERROR] IntermediaryHashesByIndex! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		// generate sophia list param
		siblingsAsStr := "["
		for index, element := range siblings {
			// index is the index where we are
			// element is the element from someSlice for where we are
			if index == len(siblings)-1 {
				siblingsAsStr += fmt.Sprintf("\"%v\"", element)
			} else {
				siblingsAsStr += fmt.Sprintf("\"%v\",", element)
			}
		}

		siblingsAsStr += "]"

		account, err := aeternity.AccountFromHexString(secretKey)
		if err != nil {
			log.Printf("[ERROR] Account error! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		node := aeternity.NewNode(aeNodeUrl, false)
		compiler := aeternity.NewCompiler(aeternity.Config.Client.Contracts.CompilerURL, false)

		signature := data.Signature[2:]
		signature = signature[len(signature)-2:] + signature[:len(signature)-2]

		callData, err := compiler.EncodeCalldata(
			contractSource,
			"migrate",
			[]string{ fmt.Sprintf(`%s`, migrationInfo.Balance),
				fmt.Sprintf(`%s`, data.AeAddress),
				fmt.Sprintf(`%d`, migrationInfo.Leaf_index), 
				fmt.Sprintf(`%s`, siblingsAsStr),
				fmt.Sprintf(`#%s`, signature)},
				backend)
		if err != nil {
			log.Printf("[ERROR] EncodeCalldata! %s\n", err)
			http.Error(w, fmt.Sprintf("Cannot encode call data. %s.", http.StatusText(500)), 500)
			return
		}

		context, n := aeternity.NewContextFromURL(aeNodeUrl, account.Address, false)

		
		var amount *big.Int = big.NewInt(0)            // aeternity.Config.Client.Contracts.Amount
		var gasPrice *big.Int = big.NewInt(1000000000) // aeternity.Config.Client.Contracts.GasPrice
		// var gas big.Int = aeternity.Config.Client.Contracts.Gas // utils.NewIntFromUint64(1e6) // 
		var gas *big.Int = utils.NewIntFromUint64(1e6) // aeternity.Config.Client.Contracts.Gas // 
		var fee *big.Int = utils.NewIntFromUint64(665480000000000)

		tx, err := context.ContractCallTx(aeContractAddress, callData, abiVersion, *amount, *gas, *gasPrice, *fee)
		if err != nil {
			log.Printf("[ERROR] ContractCallTx! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		_, txHash, _, err := aeternity.SignBroadcastTransaction(tx, account, n, "ae_devnet") // signedTxStr, hash, signature, err
		if err != nil {
			log.Printf("[ERROR] SignBroadcastTransaction! %s\n", err)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		type response struct {
			TxHash string `json:"txHash"`
			Status string `json:"status"`
		}

		status, _ := waitForTransaction(tree, node, txHash, data.EthPubKey, data.AeAddress, migrationInfo.Balance, compiler, contractSource)

		render.JSON(w, req, response{TxHash: txHash, Status: status})
	}
}

func waitForTransaction(tree *postgre.PostgresMerkleTree, aeNode *aeternity.Node, hash string, ethAddress string, aeAddress string, transferredTokens string, compiler *aeternity.Compiler, contractSource string) (result string, e error) {
	height := getHeight(aeNode)
	height, microblockHash, err := aeternity.WaitForTransactionForXBlocks(aeNode, hash, height+100)
	if err != nil {
		log.Println("Wait for transaction", err)
		return "Error", errors.New("Error")
	}

	txInfo, err := getTxInfo(hash)
	if err != nil {
		log.Println("getTxInfo", err)
		return "Error", errors.New("Error")
	} else if txInfo.CallInfo.ReturnType == "ok" {

		migrationsCount, err := compiler.DecodeCallResult("ok", txInfo.CallInfo.ReturnValue, "migrate", contractSource, backend)
		if err != nil {
			log.Println("Decode Call Result", err)
			return "Error", errors.New("Error")
		}

		temp := fmt.Sprint(migrationsCount)
		migrationsCountAsInt, err := strconv.Atoi(temp) // temp.(int)
		if err != nil {
			log.Println("Cannot parse migrations count:", migrationsCount)
			return "Error", errors.New("Error")
		}

		tree.SetMigratedToSuccess(ethAddress, hash, aeAddress)
		notifyBackendless(aeAddress, ethAddress, transferredTokens, hash, 5000+migrationsCountAsInt)
	} else if txInfo.CallInfo.ReturnType == "revert" {
		response, err := compiler.DecodeCallResult("revert", txInfo.CallInfo.ReturnValue, "migrate", contractSource, backend)
		if err != nil {
			log.Println("Decode Call Result", err)
			return "Error", errors.New("Error")
		}

		errorMessage := fmt.Sprint(response)

		return errorMessage, nil
	}

	log.Printf("[INFO] Tx Hash: [%s] Transaction was found at [%v] microblockHash: [%v]", hash, height, microblockHash)
	return txInfo.CallInfo.ReturnType, nil
}

func getTxInfo(txHash string) (*types.ContractTxInfoWrapper, error) {

	resp, err := http.Get(fmt.Sprintf("http://localhost:3001/v2/transactions/%s/info", txHash))
	if err != nil {
		log.Printf("[ERROR] txInfo.MarshalJSON()! %s\n", err)
		return nil, errors.New("Cannot get tx info")
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var data types.ContractTxInfoWrapper
	err = decoder.Decode(&data)
	if err != nil {
		log.Printf("[ERROR] json.Unmarshal(resp.Body)! %s\n", err)
		return nil, errors.New("Cannot decode response data from tx info request")
	}

	return &data, nil
}

func getHeight(aeNode *aeternity.Node) (h uint64) {
	h, err := aeNode.GetHeight()
	if err != nil {
		log.Println("Could not retrieve chain height")
		return
	}

	return
}

func notifyBackendless(aeAddress string, ethAddress string, transferedTokens string, txHash string, migrationsCount int) {

	BL_ID := "CBD0589C-4114-2D15-FF41-6FC7F3EE8800"
	BL_KEY := "39EBBD6D-5A94-0739-FF27-B17F3957B700"
	BL_URL := fmt.Sprintf("https://api.backendless.com/%s/%s", BL_ID, BL_KEY)

	if userToken == "" {
		userToken = getUserToken(BL_URL)
	}

	pushToBackendless(BL_URL, userToken, aeAddress, ethAddress, transferedTokens, txHash, migrationsCount)
}

// TODO: get or pass db credentials
func getUserToken(url string) string {

	type dbLoginCredentials struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	var dbCredentials = dbLoginCredentials{Login: "test@limechain.tech", Password: "ksdlfkaj1salfdj."}

	dataReq := map[string]interface{}{
		"login":    dbCredentials.Login,
		"password": dbCredentials.Password,
	}

	bytesRepresentation, err := json.Marshal(dataReq)
	if err != nil {
		log.Println("ERROR", err)
	}

	resp, err := http.Post(fmt.Sprintf("%s/users/login", url), "application/json", bytes.NewBuffer(bytesRepresentation))
	if err != nil {
		log.Println("ERROR", err)
	}

	defer resp.Body.Close()

	type TokenResponse struct {
		LastLogin     int    `json:"lastLogin"`
		UserStatus    string `json:"userStatus"`
		SocialAccount string `json:"socialAccount"`
		Created       int    `json:"created"`
		Name          string `json:"name"`
		Email         string `json:"email"`
		BlUserLocale  string `json:"blUserLocale"`
		// Updated     string `json:"updated"`
		ObjectId  string `json:"objectId"`
		OwnerId   string `json:"ownerId"`
		Class     string `json:"___class"`
		UserToken string `json:"user-token"`
	}

	decoder := json.NewDecoder(resp.Body)
	var data TokenResponse
	err = decoder.Decode(&data)
	if err != nil {
		log.Printf("[ERROR] json.NewDecoder(resp.Body)! %s\n", err)
	}

	return data.UserToken
}

func pushToBackendless(url string, userTkn string, aeAddress string, ethAddress string, transferedTokens string, txHash string, migrationsCount int) {

	table := "TestMigrationsLima"

	type backendlessData struct {
		PubKey          string `json:"pubKey"`
		From            string `json:"from"`
		Value           int    `json:"value"`
		DeliveryPeriod  int    `json:"deliveryPeriod"`
		Count           int    `json:"count"`
		TransactionHash string `json:"transactionHash"`
	}

	tokens, _ := strconv.Atoi(transferedTokens)

	requestData := &backendlessData{
		PubKey:          aeAddress,       // ae address
		From:            ethAddress,      // eth address
		Value:           tokens,          // migrated tokens
		DeliveryPeriod:  3,               // delivery phase ?
		Count:           migrationsCount, // migrations count
		TransactionHash: txHash,          // tx hash
	}

	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(requestData)
	if err != nil {
		log.Println("encode err")
		log.Panicln(err)
		return
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/data/%s", url, table), buf)
	if err != nil {
		log.Println(err)
		return
	}

	req.Header.Set("user-token", userTkn)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return
	}

	defer resp.Body.Close()

	type BackendlessResp struct {
		Created        int    `json:"created"`
		DeliveryPeriod int    `json:"deliveryPeriod"`
		Count          int    `json:"count"`
		Class          string `json:"___class"`
		From           string `json:"from"`
		OwnerId        string `json:"ownerId"`
		Value          string `json:"value"`
		// Updated     string `json: "updated"`
		TransactionHash string `json:"transactionHash"`
		ObjectId        string `json:"objectId"`
		PubKey          string `json:"pubKey"`
	}

	// // TODO: extract as function
	decoder := json.NewDecoder(resp.Body)
	var data BackendlessResp
	err = decoder.Decode(&data)
	if err != nil && resp.Status == "400 Bad Request" && strings.Index(err.Error(), "Not existing user token") >= 0 {
		userToken = getUserToken(url)
		log.Println("==> GET NEW TOKEN:", userToken)
		pushToBackendless(url, userToken, aeAddress, ethAddress, transferedTokens, txHash, migrationsCount)
		return
	} else if err != nil {
		log.Println(err)
		return
	}
}