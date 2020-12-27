package baseapi

import (
	"bytes"
	"errors"
	"sync"

	"github.com/aeternity/aepp-sdk-go/v5/aeternity"
	"github.com/aeternity/aepp-sdk-go/v5/utils"

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

var migrationsCount int
var customNonce uint64
var cTTL uint64

var mu sync.Mutex

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

// Migrate process request data and passed it to smart contract, after successfull response notified backendless listener
func Migrate(router chi.Router, tree *postgre.PostgresMerkleTree, secretKey string, contractSource string, envConfig types.EnvConfig) chi.Router {

	router.Post("/migrate", migrate(tree, secretKey, contractSource, envConfig))

	return router
}

func migrate(tree *postgre.PostgresMerkleTree, secretKey string, contractSource string, envConfig types.EnvConfig) http.HandlerFunc {
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

		compiler := aeternity.NewCompiler(envConfig.AECompilerURL, false)

		
		signature := data.Signature[2:]

		vValue := signature[len(signature)-2:]
		if vValue == "00" || vValue == "27" {
			vValue = "1b"
		} else if vValue == "01" || vValue == "28" {
			vValue = "1c"
		}
			
		signature = vValue + signature[:len(signature)-2]

		callData, err := compiler.EncodeCalldata(
			contractSource,
			"migrate",
			[]string{fmt.Sprintf(`%v`, migrationInfo.Balance),
				fmt.Sprintf(`%v`, data.AeAddress),
				fmt.Sprintf(`%v`, migrationInfo.Leaf_index),
				fmt.Sprintf(`%v`, siblingsAsStr),
				fmt.Sprintf("#%s", signature)},
			envConfig.AEBackend)

		if err != nil {
			log.Printf("[ERROR] EncodeCalldata! %s\n", err)
			http.Error(w, fmt.Sprintf("Cannot encode call data. %s.", http.StatusText(500)), 500)
			return
		}

		context, node := aeternity.NewContextFromURL(envConfig.AENodeUrl, account.Address, false)

		var amount *big.Int = big.NewInt(0)            // aeternity.Config.Client.Contracts.Amount
		var gasPrice *big.Int = big.NewInt(1e9) // aeternity.Config.Client.Contracts.GasPrice
		// var gas big.Int = aeternity.Config.Client.Contracts.Gas // utils.NewIntFromUint64(1e6) //
		var gasLimit *big.Int = utils.NewIntFromUint64(1e9) // aeternity.Config.Client.Contracts.Gas //
		var fee *big.Int = utils.NewIntFromUint64(2e14)

		if customNonce == 0 {
			ttl, nonce, err := context.GetTTLNonce(context.Address, aeternity.Config.Client.TTL) // ttl, nonce, err :=
			if err != nil {
				log.Printf("[ERROR] GetTTLNonce! %s\n", err)
				http.Error(w, fmt.Sprintf("GetTTLNonce. %s.", http.StatusText(500)), 500)
				return
			}

			mu.Lock()
			customNonce = nonce
			cTTL = ttl
			mu.Unlock()
		}

		mu.Lock()
		tx := aeternity.NewContractCallTx(context.Address, customNonce, envConfig.AEContractAddress, *amount, *gasLimit, *gasPrice, envConfig.AEAbiVersion, callData, *fee, cTTL)
		customNonce++
		mu.Unlock()

		txHash := ""
		maxTries := 1000

		tries := 0
		for tries < maxTries {
			_, txHash, _, err = aeternity.SignBroadcastTransaction(tx, account, node, envConfig.AENetworkID) // signedTxStr, hash, signature, err
			if err != nil {
				tries++
			} else {
				break;
			}
		}

		if tries >= maxTries - 1 {
			log.Printf("[ERROR] SignBroadcastTransaction! %s\n==>> TX: %v\n", err, tx)
			http.Error(w, http.StatusText(500), 500)
			customNonce = 0
			return
		}

		log.Println("[INFO] tx hash:", txHash)

		type response struct {
			TxHash string `json:"txHash"`
			// Status string `json:"status"`
		}

		go waitForTransaction(tree, node, txHash, data.EthPubKey, data.AeAddress, migrationInfo.Balance, compiler, contractSource, envConfig)

		render.JSON(w, req, response{TxHash: txHash})
	}
}

func waitForTransaction(tree *postgre.PostgresMerkleTree, aeNode *aeternity.Node, hash string, ethAddress string, aeAddress string, transferredTokens string, compiler *aeternity.Compiler, contractSource string, envConfig types.EnvConfig) (result string, e error) {
	height := getHeight(aeNode)
	height, microblockHash, err := aeternity.WaitForTransactionForXBlocks(aeNode, hash, height+10)
	if err != nil {
		log.Println("Wait for transaction", err)
		return "Error", errors.New("Error")
	}

	txInfo, err := getTxInfo(hash, envConfig.AENodeUrl)
	if err != nil {
		log.Println("getTxInfo", err)
		return "Error", errors.New("Error")
	} else if txInfo.CallInfo.ReturnType == "ok" {

		log.Println("[INFO] [SUCCESS] Nonce", txInfo.CallInfo.CallerNonce, "TX Hash", hash)
		migrationsCount, err := compiler.DecodeCallResult("ok", txInfo.CallInfo.ReturnValue, "migrate", contractSource, envConfig.AEBackend)
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
		notifyBackendless(envConfig, aeAddress, ethAddress, transferredTokens, hash, migrationsCountAsInt)
	} else if txInfo.CallInfo.ReturnType == "revert" {
		response, err := compiler.DecodeCallResult("revert", txInfo.CallInfo.ReturnValue, "migrate", contractSource, envConfig.AEBackend)
		if err != nil {
			log.Println("Decode Call Result", err)
			return "Error", errors.New("Error")
		}

		errorMessage := fmt.Sprint(response)

		return errorMessage, nil
	}

	log.Printf("[INFO] Tx Hash: [ %s ] Transaction was found at [ %v ] microblockHash: [ %v ]", hash, height, microblockHash)
	return txInfo.CallInfo.ReturnType, nil
}

func getTxInfo(txHash string, nodeURL string) (*types.ContractTxInfoWrapper, error) {

	resp, err := http.Get(fmt.Sprintf("%s/v2/transactions/%s/info", nodeURL, txHash))
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

func notifyBackendless(envConfig types.EnvConfig, aeAddress string, ethAddress string, transferredTokens string, txHash string, migrationsCount int) {

	if envConfig.BackendlessConfig.Url == "" || envConfig.BackendlessConfig.ID == "" || envConfig.BackendlessConfig.Key == "" || envConfig.BackendlessConfig.Login == "" || envConfig.BackendlessConfig.Password == "" {
		log.Println("[WARN] Missing backendless credentials")
		return
	}

	backendlessPushURL := fmt.Sprintf("%s/%s/%s", envConfig.BackendlessConfig.Url, envConfig.BackendlessConfig.ID, envConfig.BackendlessConfig.Key)

	if envConfig.BackendlessConfig.UserToken == "" {
		userToken := getUserToken(envConfig.BackendlessConfig.Url, envConfig.BackendlessConfig.Login, envConfig.BackendlessConfig.Password)
		appUtils.UpdateBackendlessUserToken(userToken)
	}

	pushToBackendless(backendlessPushURL, envConfig.BackendlessConfig.UserToken, envConfig.BackendlessConfig.Table, aeAddress, ethAddress, transferredTokens, txHash, migrationsCount, envConfig.BackendlessConfig.Login, envConfig.BackendlessConfig.Password)
}

func getUserToken(url string, login string, password string) string {

	dataReq := map[string]interface{}{
		"login":    login,
		"password": password,
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

func pushToBackendless(url string, userTkn string, table string, aeAddress string, ethAddress string, transferredTokens string, txHash string, migrationsCount int, backendlessLogin string, backendlessPassword string) {

	type backendlessData struct {
		PubKey          string `json:"pubKey"`
		From            string `json:"from"`
		Value           string    `json:"value"`
		DeliveryPeriod  int    `json:"deliveryPeriod"`
		Count           int    `json:"count"`
		TransactionHash string `json:"transactionHash"`
	}

	requestData := &backendlessData{
		PubKey:          aeAddress,       // ae address
		From:            ethAddress,      // eth address
		Value:           transferredTokens,          // migrated tokens
		DeliveryPeriod:  4,               // delivery phase ?!?!
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

	log.Printf("[INFO] Backendless was notified. Tx Hash: [ %s ]\n", txHash)

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
		userTkn = getUserToken(url, backendlessLogin, backendlessPassword)
		// TODO: remove this log after development
		log.Println("==> GET NEW TOKEN:", userTkn)
		pushToBackendless(url, userTkn, table, aeAddress, ethAddress, transferredTokens, txHash, migrationsCount, backendlessLogin, backendlessPassword)
		return
	} else if err != nil {
		log.Println(err)
		return
	}
}