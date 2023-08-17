package avalanche

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"

	_ "embed"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	ecommon "github.com/ethereum/go-ethereum/common"
	etypes "github.com/ethereum/go-ethereum/core/types"
	ethclient "github.com/ethereum/go-ethereum/ethclient"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gitlab.com/thorchain/thornode/bifrost/blockscanner"
	"gitlab.com/thorchain/thornode/bifrost/metrics"
	"gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/shared/evm"
	evmtypes "gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/shared/evm/types"
	"gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/signercache"
	"gitlab.com/thorchain/thornode/bifrost/pubkeymanager"
	"gitlab.com/thorchain/thornode/bifrost/thorclient"
	stypes "gitlab.com/thorchain/thornode/bifrost/thorclient/types"
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/config"
	"gitlab.com/thorchain/thornode/constants"
	memo "gitlab.com/thorchain/thornode/x/thorchain/memo"
	"golang.org/x/sync/semaphore"
)

// SolvencyReporter is to report solvency info to THORNode
type SolvencyReporter func(int64) error

//go:embed abi/router.json
var routerContractABI string

//go:embed abi/erc20.json
var erc20ContractABI string

const (
	MaxContractGas = 80000

	avaxToken       = "0x0000000000000000000000000000000000000000"
	defaultDecimals = 18 // on AVAX, consolidate all decimals to 18, in Wei
	tenGwei         = 10000000000

	// prefixTokenMeta declares prefix to use in leveldb to avoid conflicts
	// #nosec G101 this is just a prefix
	prefixTokenMeta  = `avax-tokenmeta-`
	prefixBlockMeta  = `avax-blockmeta-`
	prefixSignedMeta = `avax-signedtx-`
)

// AvalancheScanner is a scanner that understand how to interact with and scan blocks of the AVAX C-chain
type AvalancheScanner struct {
	cfg                  config.BifrostBlockScannerConfiguration
	logger               zerolog.Logger
	db                   blockscanner.ScannerStorage
	m                    *metrics.Metrics
	errCounter           *prometheus.CounterVec
	gasPriceChanged      bool
	gasPrice             *big.Int
	lastReportedGasPrice uint64
	ethClient            *ethclient.Client
	ethRpc               *evm.EthRPC
	blockMetaAccessor    evm.BlockMetaAccessor
	bridge               *thorclient.ThorchainBridge
	pubkeyMgr            pubkeymanager.PubKeyValidator
	eipSigner            etypes.Signer
	currentBlockHeight   int64
	gasCache             []*big.Int
	solvencyReporter     SolvencyReporter
	whitelistTokens      []evm.ERC20Token
	signerCacheManager   *signercache.CacheManager
	tokenManager         *evm.TokenManager

	vaultABI *abi.ABI
	erc20ABI *abi.ABI
}

// Creates a new instance of AvalancheScanner
func NewAVAXScanner(cfg config.BifrostBlockScannerConfiguration,
	storage blockscanner.ScannerStorage,
	chainID *big.Int,
	ethClient *ethclient.Client,
	ethRpc *evm.EthRPC,
	bridge *thorclient.ThorchainBridge,
	m *metrics.Metrics,
	pubkeyMgr pubkeymanager.PubKeyValidator,
	solvencyReporter SolvencyReporter,
	signerCacheManager *signercache.CacheManager,
) (*AvalancheScanner, error) {
	if storage == nil {
		return nil, errors.New("storage is nil")
	}
	if m == nil {
		return nil, errors.New("metrics manager is nil")
	}
	if ethClient == nil {
		return nil, errors.New("ETH RPC client is nil")
	}
	if pubkeyMgr == nil {
		return nil, errors.New("pubkey manager is nil")
	}
	blockMetaAccessor, err := evm.NewLevelDBBlockMetaAccessor(prefixBlockMeta, prefixSignedMeta, storage.GetInternalDb())
	if err != nil {
		return nil, fmt.Errorf("fail to create block meta accessor: %w", err)
	}

	vaultABI, erc20ABI, err := evm.GetContractABI(routerContractABI, erc20ContractABI)
	if err != nil {
		return nil, fmt.Errorf("fail to create contract abi: %w", err)
	}
	// load token list
	var whitelistTokens evm.TokenList
	if err := json.Unmarshal(tokenList, &whitelistTokens); err != nil {
		return nil, fmt.Errorf("fail to load token list,err: %w", err)
	}

	tokenManager, err := evm.NewTokenManager(storage.GetInternalDb(), prefixTokenMeta, common.AVAXAsset, defaultDecimals, cfg.HTTPRequestTimeout, whitelistTokens.Tokens, ethClient, routerContractABI, erc20ContractABI)
	if err != nil {
		return nil, fmt.Errorf("fail to create token helper: %w", err)
	}

	err = tokenManager.SaveTokenMeta("AVAX", avaxToken, defaultDecimals)
	if err != nil {
		return nil, err
	}

	return &AvalancheScanner{
		cfg:                  cfg,
		logger:               log.Logger.With().Str("module", "block_scanner").Str("chain", string(cfg.ChainID)).Logger(),
		errCounter:           m.GetCounterVec(metrics.BlockScanError(cfg.ChainID)),
		ethRpc:               ethRpc,
		db:                   storage,
		m:                    m,
		gasPrice:             big.NewInt(0),
		lastReportedGasPrice: 0,
		gasPriceChanged:      false,
		blockMetaAccessor:    blockMetaAccessor,
		bridge:               bridge,
		vaultABI:             vaultABI,
		erc20ABI:             erc20ABI,
		eipSigner:            etypes.NewLondonSigner(chainID),
		pubkeyMgr:            pubkeyMgr,
		gasCache:             make([]*big.Int, 0),
		solvencyReporter:     solvencyReporter,
		whitelistTokens:      whitelistTokens.Tokens,
		signerCacheManager:   signerCacheManager,

		tokenManager: tokenManager,
	}, nil
}

// GetGasPrice returns current gas price
func (a *AvalancheScanner) GetGasPrice() *big.Int {
	return a.gasPrice
}

// GetHeight return latest block height
func (a *AvalancheScanner) GetHeight() (int64, error) {
	height, err := a.ethRpc.GetBlockHeight()
	if err != nil {
		return -1, err
	}
	return height, nil
}

func (a *AvalancheScanner) GetNonce(addr string) (uint64, error) {
	return a.ethRpc.GetNonce(addr)
}

// FetchMemPool gets tx from mempool
func (a *AvalancheScanner) FetchMemPool(_ int64) (stypes.TxIn, error) {
	return stypes.TxIn{}, nil
}

// GetTokens return all the token meta data
func (a *AvalancheScanner) GetTokens() ([]*evmtypes.TokenMeta, error) {
	return a.tokenManager.GetTokens()
}

// FetchTxs query the AVAX C-Chain to get txs in the given block height
func (a *AvalancheScanner) FetchTxs(height, chainHeight int64) (stypes.TxIn, error) {
	if height%100 == 0 {
		a.logger.Info().Int64("height", height).Msg("Fetching txs for height")
	}
	a.currentBlockHeight = height
	block, err := a.ethRpc.GetBlock(height)
	if err != nil {
		return stypes.TxIn{}, err
	}
	txIn, err := a.processBlock(block)
	if err != nil {
		a.logger.Error().Err(err).Int64("height", height).Msg("fail to search tx in block")
		return stypes.TxIn{}, fmt.Errorf("fail to process block: %d, err:%w", height, err)
	}

	// skip reporting network fee and solvency if block more than flexibility blocks from tip
	if chainHeight-height > a.cfg.ObservationFlexibilityBlocks {
		return txIn, nil
	}

	a.reportNetworkFee(height)
	if a.solvencyReporter != nil {
		if err := a.solvencyReporter(height); err != nil {
			a.logger.Err(err).Msg("fail to report Solvency info to THORNode")
		}
	}

	return txIn, nil
}

// processBlock extracts transactions from block
func (a *AvalancheScanner) processBlock(block *etypes.Block) (stypes.TxIn, error) {
	txIn := stypes.TxIn{
		Chain:           common.AVAXChain,
		TxArray:         nil,
		Filtered:        false,
		MemPool:         false,
		SentUnFinalised: false,
		Finalised:       false,
	}

	// Collect gas prices of txs in current block
	var txsGas []*big.Int
	for _, tx := range block.Transactions() {
		txsGas = append(txsGas, tx.GasPrice())
	}
	a.updateGasPrice(txsGas)

	if block.Transactions().Len() == 0 {
		return txIn, nil
	}

	txInBlock, err := a.getTxIn(block)
	if err != nil {
		return txIn, err
	}
	if len(txInBlock.TxArray) > 0 {
		txIn.TxArray = append(txIn.TxArray, txInBlock.TxArray...)
	}
	return txIn, nil
}

// getTxIn builds a TxIn from an Avalanche Block
func (a *AvalancheScanner) getTxIn(block *etypes.Block) (stypes.TxIn, error) {
	txInbound := stypes.TxIn{
		Chain:    common.AVAXChain,
		Filtered: false,
		MemPool:  false,
	}

	sem := semaphore.NewWeighted(a.cfg.Concurrency)
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}

	processTx := func(tx *etypes.Transaction) {
		defer wg.Done()
		if err := sem.Acquire(context.Background(), 1); err != nil {
			a.logger.Err(err).Msg("fail to acquire semaphore")
			return
		}
		defer sem.Release(1)

		if tx.To() == nil {
			return
		}
		// just try to remove the transaction hash from key value store
		// it doesn't matter whether the transaction is ours or not , success or failure
		// as long as the transaction id matches
		if err := a.blockMetaAccessor.RemoveSignedTxItem(tx.Hash().String()); err != nil {
			a.logger.Err(err).Str("tx hash", tx.Hash().String()).Msg("fail to remove signed tx item")
		}

		txInItem, err := a.getTxInItem(tx)
		if err != nil {
			a.logger.Error().Err(err).Str("hash", tx.Hash().Hex()).Msg("fail to get one tx from server")
			return
		}
		if txInItem == nil {
			return
		}
		// sometimes if a transaction failed due to gas problem , it will have no `to` address
		if len(txInItem.To) == 0 {
			return
		}
		if len([]byte(txInItem.Memo)) > constants.MaxMemoSize {
			return
		}
		txInItem.BlockHeight = block.Number().Int64()
		mu.Lock()
		txInbound.TxArray = append(txInbound.TxArray, *txInItem)
		mu.Unlock()
	}

	// process txs in parallel
	for _, tx := range block.Transactions() {
		wg.Add(1)
		go processTx(tx)
	}
	wg.Wait()

	if len(txInbound.TxArray) == 0 {
		a.logger.Debug().Int64("block", int64(block.NumberU64())).Msg("no tx need to be processed in this block")
		return stypes.TxIn{}, nil
	}
	txInbound.Count = strconv.Itoa(len(txInbound.TxArray))
	return txInbound, nil
}

// getTxInItem builds a TxInItem from an Avalanche Transaction
func (a *AvalancheScanner) getTxInItem(tx *etypes.Transaction) (*stypes.TxInItem, error) {
	if tx == nil || tx.To() == nil {
		return nil, nil
	}

	receipt, err := a.ethRpc.GetReceipt(tx.Hash().Hex())
	if err != nil {
		if errors.Is(err, ethereum.NotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("fail to get transaction receipt: %w", err)
	}

	if receipt.Status != 1 {
		// If a transaction fails, it needs to be removed from the Signer Cache
		// so it can be retried
		if a.signerCacheManager != nil {
			a.signerCacheManager.RemoveSigned(tx.Hash().String())
		}
		a.logger.Debug().Str("tx hash", tx.Hash().String()).Uint64("failed status", receipt.Status).Msg("tx failed, skip")
		return a.getTxInFromFailedTransaction(tx, receipt), nil
	}

	if a.isToValidContractAddress(tx.To(), true) {
		return a.getTxInFromSmartContract(tx, receipt)
	}
	a.logger.Debug().Str("tx hash", tx.Hash().String()).Str("tx to", tx.To().String()).Msg("not a valid contract")
	return a.getTxInFromTransaction(tx)
}

/* Gas-related functions */

// updateGasPrice calculates current gas price to report to thornode using the gas cache
func (a *AvalancheScanner) updateGasPrice(prices []*big.Int) {
	// skip empty blocks
	if len(prices) == 0 {
		return
	}

	// find the median gas price in the block
	sort.Slice(prices, func(i, j int) bool { return prices[i].Cmp(prices[j]) == -1 })
	gasPrice := prices[len(prices)/2]

	// add to the cache
	a.gasCache = append(a.gasCache, gasPrice)
	if len(a.gasCache) > a.cfg.GasCacheBlocks {
		a.gasCache = a.gasCache[(len(a.gasCache) - a.cfg.GasCacheBlocks):]
	}

	// skip update unless cache is full
	if len(a.gasCache) < a.cfg.GasCacheBlocks {
		return
	}

	// compute the median of the median prices in the cache
	medians := []*big.Int{}
	medians = append(medians, a.gasCache...)
	sort.Slice(medians, func(i, j int) bool { return medians[i].Cmp(medians[j]) == -1 })
	median := medians[len(medians)/2]

	// round the price up to avoid fee noise
	resolution := big.NewInt(a.cfg.GasPriceResolution)
	if median.Cmp(resolution) != 1 {
		a.gasPrice = resolution
	} else {
		median.Sub(median, big.NewInt(1))
		median.Quo(median, big.NewInt(a.cfg.GasPriceResolution))
		median.Add(median, big.NewInt(1))
		median.Mul(median, big.NewInt(a.cfg.GasPriceResolution))
		a.gasPrice = median
	}

	// record metrics
	gasPriceFloat, _ := new(big.Float).SetInt64(a.gasPrice.Int64()).Float64()
	a.m.GetGauge(metrics.GasPrice(common.AVAXChain)).Set(gasPriceFloat)
	a.m.GetCounter(metrics.GasPriceChange(common.AVAXChain)).Inc()
}

// reportNetworkFee reports current network fee to thornode
func (a *AvalancheScanner) reportNetworkFee(height int64) {
	gasPrice := a.GetGasPrice()

	// skip posting if there is not yet a fee
	if gasPrice.Cmp(big.NewInt(0)) == 0 {
		return
	}

	// skip fee if less than 1 resolution away from the last
	feeDelta := new(big.Int).Sub(gasPrice, big.NewInt(int64(a.lastReportedGasPrice)))
	feeDelta.Abs(feeDelta)
	if a.lastReportedGasPrice != 0 && feeDelta.Cmp(big.NewInt(a.cfg.GasPriceResolution)) != 1 {
		return
	}

	// gas price to 1e8
	tcGasPrice := new(big.Int).Div(gasPrice, big.NewInt(common.One*100))

	// post to thorchain
	if _, err := a.bridge.PostNetworkFee(height, common.AVAXChain, MaxContractGas, tcGasPrice.Uint64()); err != nil {
		a.logger.Err(err).Msg("fail to post AVAX chain single transfer fee to THORNode")
	} else {
		a.lastReportedGasPrice = gasPrice.Uint64()
	}
}

/* Transaction parsing */

func (a *AvalancheScanner) getTxInFromTransaction(tx *etypes.Transaction) (*stypes.TxInItem, error) {
	txInItem := &stypes.TxInItem{
		Tx: tx.Hash().Hex()[2:],
	}
	asset := common.AVAXAsset
	sender, err := a.eipSigner.Sender(tx)
	if err != nil {
		return nil, fmt.Errorf("fail to get sender: %w", err)
	}
	txInItem.Sender = strings.ToLower(sender.String())
	txInItem.To = strings.ToLower(tx.To().String())
	// this is native, thus memo is data field
	data := tx.Data()
	if len(data) > 0 {
		memo, err := hex.DecodeString(string(data))
		if err != nil {
			txInItem.Memo = string(data)
		} else {
			txInItem.Memo = string(memo)
		}
	}
	avaxValue := a.convertAmount(avaxToken, tx.Value())
	txInItem.Coins = append(txInItem.Coins, common.NewCoin(asset, avaxValue))
	txGasPrice := tx.GasPrice()
	if txGasPrice.Cmp(big.NewInt(tenGwei)) < 0 {
		txGasPrice = big.NewInt(tenGwei)
	}
	txInItem.Gas = common.MakeAVAXGas(txGasPrice, tx.Gas())
	txInItem.Gas[0].Asset = common.AVAXAsset

	if txInItem.Coins.IsEmpty() {
		a.logger.Debug().Msg("there is no coin in this tx, ignore")
		return nil, nil
	}
	return txInItem, nil
}

// isToValidContractAddress this method make sure the transaction to address is to THORChain router or a whitelist address
func (a *AvalancheScanner) isToValidContractAddress(addr *ecommon.Address, includeWhiteList bool) bool {
	// get the smart contract used by thornode
	contractAddresses := a.pubkeyMgr.GetContracts(common.AVAXChain)
	if includeWhiteList {
		contractAddresses = append(contractAddresses, whitelistSmartContractAddress...)
	}

	// combine the whitelist smart contract address
	for _, item := range contractAddresses {
		if strings.EqualFold(item.String(), addr.String()) {
			return true
		}
	}
	return false
}

// getTxInFromSmartContract returns txInItem
func (a *AvalancheScanner) getTxInFromSmartContract(tx *etypes.Transaction, receipt *etypes.Receipt) (*stypes.TxInItem, error) {
	txInItem := &stypes.TxInItem{
		Tx: tx.Hash().Hex()[2:],
	}
	sender, err := a.eipSigner.Sender(tx)
	if err != nil {
		return nil, fmt.Errorf("fail to get sender: %w", err)
	}
	txInItem.Sender = strings.ToLower(sender.String())
	// 1 is Transaction success state
	if receipt.Status != 1 {
		a.logger.Debug().Str("tx hash", tx.Hash().String()).Uint64("failed status", receipt.Status).Msg("tx failed, skip")
		return nil, nil
	}
	p := evm.NewSmartContractLogParser(a.isToValidContractAddress,
		a.tokenManager.GetAssetFromTokenAddress,
		a.tokenManager.GetTokenDecimalsForTHORChain,
		a.tokenManager.ConvertAmount,
		a.vaultABI,
		common.AVAXAsset)

	// txInItem will be changed in p.getTxInItem function, so if the function return an error
	// txInItem should be abandoned
	isVaultTransfer, err := p.GetTxInItem(receipt.Logs, txInItem)
	if err != nil {
		return nil, fmt.Errorf("fail to parse logs, err: %w", err)
	}
	if isVaultTransfer {
		contractAddresses := a.pubkeyMgr.GetContracts(common.AVAXChain)
		isDirectlyToRouter := false
		for _, item := range contractAddresses {
			if strings.EqualFold(item.String(), tx.To().String()) {
				isDirectlyToRouter = true
				break
			}
		}
		if isDirectlyToRouter {
			// it is important to keep this part outside the above loop, as when we do router upgrade, which might generate multiple deposit event, along with tx that has avax value in it
			avaxValue := cosmos.NewUintFromBigInt(tx.Value())
			if !avaxValue.IsZero() {
				avaxValue = a.tokenManager.ConvertAmount(avaxToken, tx.Value())
				if txInItem.Coins.GetCoin(common.AVAXAsset).IsEmpty() && !avaxValue.IsZero() {
					txInItem.Coins = append(txInItem.Coins, common.NewCoin(common.AVAXAsset, avaxValue))
				}
			}
		}
	}
	a.logger.Info().Str("tx hash", txInItem.Tx).Str("gas price", tx.GasPrice().String()).Uint64("gas used", receipt.GasUsed).Uint64("tx status", receipt.Status).Msg("txInItem parsed from smart contract")

	// under no circumstance AVAX gas price will be less than 1 Gwei, unless it is in dev environment
	txGasPrice := tx.GasPrice()
	if txGasPrice.Cmp(big.NewInt(tenGwei)) < 0 {
		txGasPrice = big.NewInt(tenGwei)
	}
	txInItem.Gas = common.MakeAVAXGas(txGasPrice, receipt.GasUsed)
	if txInItem.Coins.IsEmpty() {
		return nil, nil
	}
	return txInItem, nil
}

// getTxInFromFailedTransaction when a transaction failed due to out of gas, this method will check whether the transaction is an outbound
// it fake a txInItem if the failed transaction is an outbound , and report it back to THORNode, thus the gas fee can be subsidised
// need to know that this will also cause the yggdrasil / asgard that send out the outbound to be slashed 1.5x gas
// it is for security purpose
func (a *AvalancheScanner) getTxInFromFailedTransaction(tx *etypes.Transaction, receipt *etypes.Receipt) *stypes.TxInItem {
	if receipt.Status == 1 {
		a.logger.Info().Str("hash", tx.Hash().String()).Msg("success transaction should not get into getTxInFromFailedTransaction")
		return nil
	}
	fromAddr, err := a.eipSigner.Sender(tx)
	if err != nil {
		a.logger.Err(err).Msg("fail to get from address")
		return nil
	}
	ok, cif := a.pubkeyMgr.IsValidPoolAddress(fromAddr.String(), common.AVAXChain)
	if !ok || cif.IsEmpty() {
		return nil
	}
	txGasPrice := tx.GasPrice()
	if txGasPrice.Cmp(big.NewInt(tenGwei)) < 0 {
		txGasPrice = big.NewInt(tenGwei)
	}
	txHash := tx.Hash().Hex()[2:]

	return &stypes.TxInItem{
		Tx:     txHash,
		Memo:   memo.NewOutboundMemo(common.TxID(txHash)).String(),
		Sender: strings.ToLower(fromAddr.String()),
		To:     strings.ToLower(tx.To().String()),
		Coins:  common.NewCoins(common.NewCoin(common.AVAXAsset, cosmos.NewUint(1))),
		Gas:    common.MakeAVAXGas(txGasPrice, tx.Gas()),
	}
}

// convertAmount will convert the amount to 1e8 , the decimals used by THORChain
func (a *AvalancheScanner) convertAmount(token string, amt *big.Int) cosmos.Uint {
	return a.tokenManager.ConvertAmount(token, amt)
}

// IsAVAX return true if the token address equals to avaxToken address
func IsAVAX(token string) bool {
	return strings.EqualFold(token, avaxToken)
}
