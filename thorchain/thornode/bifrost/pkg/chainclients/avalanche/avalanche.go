package avalanche

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/ethereum/go-ethereum/accounts/abi"
	ecommon "github.com/ethereum/go-ethereum/common"
	etypes "github.com/ethereum/go-ethereum/core/types"
	ethclient "github.com/ethereum/go-ethereum/ethclient"
	"github.com/hashicorp/go-multierror"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"gitlab.com/thorchain/thornode/bifrost/blockscanner"
	"gitlab.com/thorchain/thornode/bifrost/metrics"
	"gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/runners"
	"gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/shared/evm"
	"gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/signercache"
	"gitlab.com/thorchain/thornode/bifrost/pubkeymanager"
	"gitlab.com/thorchain/thornode/bifrost/thorclient"
	stypes "gitlab.com/thorchain/thornode/bifrost/thorclient/types"
	"gitlab.com/thorchain/thornode/bifrost/tss"
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/config"
	"gitlab.com/thorchain/thornode/constants"
	mem "gitlab.com/thorchain/thornode/x/thorchain/memo"
	tssp "gitlab.com/thorchain/tss/go-tss/tss"
)

const (
	maxGasLimit = 400000
)

// AvalancheClient is a structure to sign and broadcast tx to the Avalanche C-Chain
type AvalancheClient struct {
	logger                  zerolog.Logger
	cfg                     config.BifrostChainConfiguration
	localPubKey             common.PubKey
	kw                      *evm.KeySignWrapper
	ethClient               *ethclient.Client
	avaxScanner             *AvalancheScanner
	bridge                  *thorclient.ThorchainBridge
	blockScanner            *blockscanner.BlockScanner
	vaultABI                *abi.ABI
	pubkeyMgr               pubkeymanager.PubKeyValidator
	poolMgr                 thorclient.PoolManager
	tssKeySigner            *tss.KeySign
	wg                      *sync.WaitGroup
	stopchan                chan struct{}
	globalSolvencyQueue     chan stypes.Solvency
	signerCacheManager      *signercache.CacheManager
	lastSolvencyCheckHeight int64
	chain                   common.Chain
}

// NewAvalancheClient creates new instance of an AvalancheClient
func NewAvalancheClient(thorKeys *thorclient.Keys,
	cfg config.BifrostChainConfiguration,
	server *tssp.TssServer,
	bridge *thorclient.ThorchainBridge,
	m *metrics.Metrics,
	pubkeyMgr pubkeymanager.PubKeyValidator,
	poolMgr thorclient.PoolManager,
) (*AvalancheClient, error) {
	if thorKeys == nil {
		return nil, fmt.Errorf("fail to create EVM client, thor keys is empty")
	}
	tssKm, err := tss.NewKeySign(server, bridge)
	if err != nil {
		return nil, fmt.Errorf("fail to create tss signer: %w", err)
	}

	priv, err := thorKeys.GetPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("fail to get private key: %w", err)
	}

	temp, err := codec.ToTmPubKeyInterface(priv.PubKey())
	if err != nil {
		return nil, fmt.Errorf("fail to get tm pub key: %w", err)
	}
	pk, err := common.NewPubKeyFromCrypto(temp)
	if err != nil {
		return nil, fmt.Errorf("fail to get pub key: %w", err)
	}

	if bridge == nil {
		return nil, errors.New("THORChain bridge is nil")
	}
	if pubkeyMgr == nil {
		return nil, errors.New("pubkey manager is nil")
	}
	if poolMgr == nil {
		return nil, errors.New("pool manager is nil")
	}
	evmPrivateKey, err := evm.GetPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	rpcClient, err := evm.NewEthRPC(cfg.RPCHost, cfg.BlockScanner.HTTPRequestTimeout, common.AVAXAsset.String())
	if err != nil {
		return nil, fmt.Errorf("fail to create ETH rpc host(%s): %w", cfg.RPCHost, err)
	}

	ethClient, err := ethclient.Dial(cfg.RPCHost)
	if err != nil {
		return nil, fmt.Errorf("fail to dial ETH rpc host(%s): %w", cfg.RPCHost, err)
	}

	chainID, err := getChainID(ethClient, cfg.BlockScanner.HTTPRequestTimeout)
	if err != nil {
		return nil, err
	}
	if chainID.Uint64() == 0 {
		return nil, fmt.Errorf("chain id is: %d , invalid", chainID.Uint64())
	}

	keysignWrapper, err := evm.NewKeySignWrapper(evmPrivateKey, pk, tssKm, chainID, common.AVAXChain.String())
	if err != nil {
		return nil, fmt.Errorf("fail to create %s key sign wrapper: %w", common.AVAXChain, err)
	}
	vaultABI, _, err := evm.GetContractABI(routerContractABI, erc20ContractABI)
	if err != nil {
		return nil, fmt.Errorf("fail to get contract abi: %w", err)
	}
	pubkeyMgr.GetPubKeys()
	c := &AvalancheClient{
		logger:       log.With().Str("module", "avalanche").Logger(),
		cfg:          cfg,
		ethClient:    ethClient,
		localPubKey:  pk,
		kw:           keysignWrapper,
		bridge:       bridge,
		vaultABI:     vaultABI,
		pubkeyMgr:    pubkeyMgr,
		poolMgr:      poolMgr,
		tssKeySigner: tssKm,
		wg:           &sync.WaitGroup{},
		stopchan:     make(chan struct{}),
		chain:        common.AVAXChain,
	}

	var path string // if not set later, will in memory storage
	if len(c.cfg.BlockScanner.DBPath) > 0 {
		path = fmt.Sprintf("%s/%s", c.cfg.BlockScanner.DBPath, c.cfg.BlockScanner.ChainID)
	}
	storage, err := blockscanner.NewBlockScannerStorage(path)
	if err != nil {
		return c, fmt.Errorf("fail to create blockscanner storage: %w", err)
	}
	signerCacheManager, err := signercache.NewSignerCacheManager(storage.GetInternalDb())
	if err != nil {
		return nil, fmt.Errorf("fail to create signer cache manager")
	}

	c.signerCacheManager = signerCacheManager
	c.avaxScanner, err = NewAVAXScanner(c.cfg.BlockScanner, storage, chainID, ethClient, rpcClient, c.bridge, m, pubkeyMgr, c.ReportSolvency, signerCacheManager)
	if err != nil {
		return c, fmt.Errorf("fail to create avax block scanner: %w", err)
	}

	c.blockScanner, err = blockscanner.NewBlockScanner(c.cfg.BlockScanner, storage, m, c.bridge, c.avaxScanner)
	if err != nil {
		return c, fmt.Errorf("fail to create block scanner: %w", err)
	}
	localNodeAddress, err := c.localPubKey.GetAddress(common.AVAXChain)
	if err != nil {
		c.logger.Err(err).Str("chain", string(common.AVAXChain)).Msg("failed to get local node address")
	}
	c.logger.Info().Str("chain", string(common.AVAXChain)).Str("address", localNodeAddress.String()).Msg("local node address")

	return c, nil
}

func (c *AvalancheClient) getContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), c.cfg.BlockScanner.HTTPRequestTimeout)
}

// getChainID retrieves the chain id from the Avalanche node, and determines if we are running on test net by checking the status
// when it fails to get chain id, it will assume LocalNet
func getChainID(client *ethclient.Client, timeout time.Duration) (*big.Int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("fail to get chain id, err: %w", err)
	}
	return chainID, err
}

// Start to monitor the AVAX C-Chain
func (c *AvalancheClient) Start(globalTxsQueue chan stypes.TxIn, globalErrataQueue chan stypes.ErrataBlock, globalSolvencyQueue chan stypes.Solvency) {
	c.globalSolvencyQueue = globalSolvencyQueue
	c.tssKeySigner.Start()
	c.blockScanner.Start(globalTxsQueue)
	c.wg.Add(1)
	go c.unstuck()
	c.wg.Add(1)
	go runners.SolvencyCheckRunner(c.GetChain(), c, c.bridge, c.stopchan, c.wg, constants.ThorchainBlockTime)
}

// Stop monitoring the AVAX C-Chain
func (c *AvalancheClient) Stop() {
	c.tssKeySigner.Stop()
	c.blockScanner.Stop()
	close(c.stopchan)
	c.wg.Wait()
}

// IsBlockScannerHealthy returns if the block scanner is healthy or not
func (c *AvalancheClient) IsBlockScannerHealthy() bool {
	return c.blockScanner.IsHealthy()
}

// GetConfig return the configurations used by AVAX chain client
func (c *AvalancheClient) GetConfig() config.BifrostChainConfiguration {
	return c.cfg
}

// GetChain gets chain
func (c *AvalancheClient) GetChain() common.Chain {
	return c.chain
}

// GetHeight gets height from avax scanner
func (c *AvalancheClient) GetHeight() (int64, error) {
	return c.avaxScanner.GetHeight()
}

// GetBalance call smart contract to find out the balance of the given address and token
func (c *AvalancheClient) GetBalance(addr, token string, height *big.Int) (*big.Int, error) {
	contractAddresses := c.pubkeyMgr.GetContracts(common.AVAXChain)
	c.logger.Debug().Interface("contractAddresses", contractAddresses).Msg("got contracts")
	if len(contractAddresses) == 0 {
		return nil, fmt.Errorf("fail to get contract address")
	}

	return c.avaxScanner.tokenManager.GetBalance(addr, token, height, contractAddresses[0].String())
}

// GetAddress returns the current signer address, it will be bech32 encoded address
func (c *AvalancheClient) GetAddress(poolPubKey common.PubKey) string {
	addr, err := poolPubKey.GetAddress(common.AVAXChain)
	if err != nil {
		c.logger.Error().Err(err).Str("pool_pub_key", poolPubKey.String()).Msg("fail to get pool address")
		return ""
	}
	return addr.String()
}

// GetBalances gets all the balances of the given address
func (c *AvalancheClient) GetBalances(addr string, height *big.Int) (common.Coins, error) {
	// for all the tokens the chain client has dealt with before
	tokens, err := c.avaxScanner.GetTokens()
	if err != nil {
		return nil, fmt.Errorf("fail to get all the tokens: %w", err)
	}
	coins := common.Coins{}
	for _, token := range tokens {
		balance, err := c.GetBalance(addr, token.Address, height)
		if err != nil {
			c.logger.Err(err).Str("token", token.Address).Msg("fail to get balance for token")
			continue
		}
		asset := common.AVAXAsset
		if !IsAVAX(token.Address) {
			asset, err = common.NewAsset(fmt.Sprintf("AVAX.%s-%s", token.Symbol, token.Address))
			if err != nil {
				return nil, err
			}
		}
		bal := c.avaxScanner.convertAmount(token.Address, balance)
		coins = append(coins, common.NewCoin(asset, bal))
	}

	return coins.Distinct(), nil
}

// GetAccount gets account by address in avax client
func (c *AvalancheClient) GetAccount(pk common.PubKey, height *big.Int) (common.Account, error) {
	addr := c.GetAddress(pk)
	nonce, err := c.avaxScanner.GetNonce(addr)
	if err != nil {
		return common.Account{}, err
	}
	coins, err := c.GetBalances(addr, height)
	if err != nil {
		return common.Account{}, err
	}
	account := common.NewAccount(int64(nonce), 0, coins, false)
	return account, nil
}

// GetAccountByAddress return account information
func (c *AvalancheClient) GetAccountByAddress(address string, height *big.Int) (common.Account, error) {
	nonce, err := c.avaxScanner.GetNonce(address)
	if err != nil {
		return common.Account{}, err
	}
	coins, err := c.GetBalances(address, height)
	if err != nil {
		return common.Account{}, err
	}
	account := common.NewAccount(int64(nonce), 0, coins, false)
	return account, nil
}

/* Gas-related methods */

// GetGasFee gets gas fee
func (c *AvalancheClient) GetGasFee(gas uint64) common.Gas {
	return common.GetAVAXGasFee(c.GetGasPrice(), gas)
}

// GetGasPrice gets gas price from eth scanner
func (c *AvalancheClient) GetGasPrice() *big.Int {
	gasPrice := c.avaxScanner.GetGasPrice()
	return gasPrice
}

func (c *AvalancheClient) getSmartContractAddr(pubkey common.PubKey) common.Address {
	return c.pubkeyMgr.GetContract(common.AVAXChain, pubkey)
}

func (c *AvalancheClient) getSmartContractByAddress(addr common.Address) common.Address {
	for _, pk := range c.pubkeyMgr.GetPubKeys() {
		avaxAddr, err := pk.GetAddress(common.AVAXChain)
		if err != nil {
			return common.NoAddress
		}
		if avaxAddr.Equals(addr) {
			return c.pubkeyMgr.GetContract(common.AVAXChain, pk)
		}
	}
	return common.NoAddress
}

func getTokenAddressFromAsset(asset common.Asset) string {
	if asset.Equals(common.AVAXAsset) {
		return avaxToken
	}
	allParts := strings.Split(asset.Symbol.String(), "-")
	return allParts[len(allParts)-1]
}

func (c *AvalancheClient) convertSigningAmount(amt *big.Int, token string) *big.Int {
	return c.avaxScanner.tokenManager.ConvertSigningAmount(amt, token)
}

func (c *AvalancheClient) convertThorchainAmountToWei(amt *big.Int) *big.Int {
	return big.NewInt(0).Mul(amt, big.NewInt(common.One*100))
}

// getOutboundTxData generates the tx data and tx value of the outbound Router Contract call, and checks if the router contract has been updated
func (c *AvalancheClient) getOutboundTxData(txOutItem stypes.TxOutItem, memo mem.Memo, contractAddr common.Address) ([]byte, bool, *big.Int, error) {
	var data []byte
	var err error
	var tokenAddr string
	value := big.NewInt(0)
	avaxValue := big.NewInt(0)
	hasRouterUpdated := false

	if len(txOutItem.Coins) == 1 {
		coin := txOutItem.Coins[0]
		tokenAddr = getTokenAddressFromAsset(coin.Asset)
		value = value.Add(value, coin.Amount.BigInt())
		value = c.convertSigningAmount(value, tokenAddr)
		if IsAVAX(tokenAddr) {
			avaxValue = value
		}
	}

	toAddr := ecommon.HexToAddress(txOutItem.ToAddress.String())

	switch memo.GetType() {
	case mem.TxOutbound, mem.TxRefund, mem.TxRagnarok:
		if txOutItem.Aggregator == "" {
			data, err = c.vaultABI.Pack("transferOut", toAddr, ecommon.HexToAddress(tokenAddr), value, txOutItem.Memo)
			if err != nil {
				return nil, hasRouterUpdated, nil, fmt.Errorf("fail to create data to call smart contract(transferOut): %w", err)
			}
		} else {
			memoType := memo.GetType()
			if memoType == mem.TxRefund || memoType == mem.TxRagnarok {
				return nil, hasRouterUpdated, nil, fmt.Errorf("%s can't use transferOutAndCall", memoType)
			}
			c.logger.Info().Msgf("aggregator target asset address: %s", txOutItem.AggregatorTargetAsset)
			if avaxValue.Uint64() == 0 {
				return nil, hasRouterUpdated, nil, fmt.Errorf("transferOutAndCall can only be used when outbound asset is AVAX")
			}
			targetLimit := txOutItem.AggregatorTargetLimit
			if targetLimit == nil {
				zeroLimit := cosmos.ZeroUint()
				targetLimit = &zeroLimit
			}
			aggAddr := ecommon.HexToAddress(txOutItem.Aggregator)
			targetAddr := ecommon.HexToAddress(txOutItem.AggregatorTargetAsset)
			// when address can't be round trip , the tx out item will be dropped
			if !strings.EqualFold(aggAddr.String(), txOutItem.Aggregator) {
				c.logger.Error().Msgf("aggregator address can't roundtrip , ignore tx (%s != %s)", txOutItem.Aggregator, aggAddr.String())
				return nil, hasRouterUpdated, nil, nil
			}
			if !strings.EqualFold(targetAddr.String(), txOutItem.AggregatorTargetAsset) {
				c.logger.Error().Msgf("aggregator target asset address can't roundtrip , ignore tx (%s != %s)", txOutItem.AggregatorTargetAsset, targetAddr.String())
				return nil, hasRouterUpdated, nil, nil
			}
			data, err = c.vaultABI.Pack("transferOutAndCall", aggAddr, targetAddr, toAddr, targetLimit.BigInt(), txOutItem.Memo)
			if err != nil {
				return nil, hasRouterUpdated, nil, fmt.Errorf("fail to create data to call smart contract(transferOutAndCall): %w", err)
			}
		}
	case mem.TxMigrate, mem.TxYggdrasilFund:
		if txOutItem.Aggregator != "" || txOutItem.AggregatorTargetAsset != "" {
			return nil, hasRouterUpdated, nil, fmt.Errorf("migration / yggdrasil+ can't use aggregator")
		}
		if IsAVAX(tokenAddr) {
			data, err = c.vaultABI.Pack("transferOut", toAddr, ecommon.HexToAddress(tokenAddr), value, txOutItem.Memo)
			if err != nil {
				return nil, hasRouterUpdated, nil, fmt.Errorf("fail to create data to call smart contract(transferOut): %w", err)
			}
		} else {
			newSmartContractAddr := c.getSmartContractByAddress(txOutItem.ToAddress)
			if newSmartContractAddr.IsEmpty() {
				return nil, hasRouterUpdated, nil, fmt.Errorf("fail to get new smart contract address")
			}
			data, err = c.vaultABI.Pack("transferAllowance", ecommon.HexToAddress(newSmartContractAddr.String()), toAddr, ecommon.HexToAddress(tokenAddr), value, txOutItem.Memo)
			if err != nil {
				return nil, hasRouterUpdated, nil, fmt.Errorf("fail to create data to call smart contract(transferAllowance): %w", err)
			}
		}
	case mem.TxYggdrasilReturn:
		if txOutItem.Aggregator != "" || txOutItem.AggregatorTargetAsset != "" {
			return nil, hasRouterUpdated, nil, fmt.Errorf("yggdrasil- can't use aggregator")
		}
		newSmartContractAddr := c.getSmartContractByAddress(txOutItem.ToAddress)
		if newSmartContractAddr.IsEmpty() {
			return nil, hasRouterUpdated, nil, fmt.Errorf("fail to get new smart contract address")
		}
		hasRouterUpdated = !newSmartContractAddr.Equals(contractAddr)

		var coins []evm.RouterCoin
		for _, item := range txOutItem.Coins {
			assetAddr := getTokenAddressFromAsset(item.Asset)
			assetAmt := c.convertSigningAmount(item.Amount.BigInt(), assetAddr)
			if IsAVAX(assetAddr) {
				avaxValue = assetAmt
				continue
			}
			coins = append(coins, evm.RouterCoin{
				Asset:  ecommon.HexToAddress(assetAddr),
				Amount: assetAmt,
			})
		}
		data, err = c.vaultABI.Pack("returnVaultAssets", ecommon.HexToAddress(newSmartContractAddr.String()), toAddr, coins, txOutItem.Memo)
		if err != nil {
			return nil, hasRouterUpdated, nil, fmt.Errorf("fail to create data to call smart contract(transferVaultAssets): %w", err)
		}
	}
	return data, hasRouterUpdated, avaxValue, nil
}

func (c *AvalancheClient) buildOutboundTx(txOutItem stypes.TxOutItem, memo mem.Memo) (*etypes.Transaction, error) {
	contractAddr := c.getSmartContractAddr(txOutItem.VaultPubKey)
	if contractAddr.IsEmpty() {
		// we may be churning from a vault that does not have a contract
		// try getting the toAddress (new vault) contract instead
		memo, err := mem.ParseMemo(common.LatestVersion, txOutItem.Memo)
		if err != nil {
			return nil, fmt.Errorf("fail to parse memo during empty contract recovery(%s):%w", txOutItem.Memo, err)
		}
		if memo.GetType() == mem.TxMigrate {
			contractAddr = c.getSmartContractByAddress(txOutItem.ToAddress)
		}
		if contractAddr.IsEmpty() {
			return nil, fmt.Errorf("can't sign tx, fail to get smart contract address")
		}
	}

	fromAddr, err := txOutItem.VaultPubKey.GetAddress(common.AVAXChain)
	if err != nil {
		return nil, fmt.Errorf("fail to get AVAX address for pub key(%s): %w", txOutItem.VaultPubKey, err)
	}

	txData, hasRouterUpdated, avaxValue, err := c.getOutboundTxData(txOutItem, memo, contractAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get outbound tx data %w", err)
	}
	if avaxValue == nil {
		avaxValue = cosmos.ZeroUint().BigInt()
	}

	nonce, err := c.avaxScanner.GetNonce(fromAddr.String())
	if err != nil {
		return nil, fmt.Errorf("fail to fetch account(%s) nonce : %w", fromAddr, err)
	}

	// compare the gas rate prescribed by THORChain against the price it can get from the chain
	// ensure signer always pay enough higher gas price
	// GasRate from thorchain is in 1e8, need to convert to Wei
	gasRate := c.convertThorchainAmountToWei(big.NewInt(txOutItem.GasRate))
	if gasRate.Cmp(c.GetGasPrice()) < 0 {
		gasRate = c.GetGasPrice()
	}
	// outbound tx always send to smart contract address
	estimatedAVAXValue := big.NewInt(0)
	if avaxValue.Uint64() > 0 {
		// when the AVAX value is non-zero, here override it with a fixed value to estimate gas
		// when AVAX value is non-zero, if we send the real value for estimate gas, sometimes it will fail, for many reasons, a few I saw during test
		// 1. insufficient fund
		// 2. gas required exceeds allowance
		// as long as we pass in an AVAX value , which we almost guarantee it will not exceed the AVAX balance , so we can avoid the above two errors
		estimatedAVAXValue = estimatedAVAXValue.SetInt64(21000)
	}
	createdTx := etypes.NewTransaction(nonce, ecommon.HexToAddress(contractAddr.String()), estimatedAVAXValue, MaxContractGas, gasRate, txData)
	estimatedGas, err := c.avaxScanner.ethRpc.EstimateGas(fromAddr.String(), createdTx)
	if err != nil {
		// in an edge case that vault doesn't have enough fund to fulfill an outbound transaction , it will fail to estimate gas
		// the returned error is `execution reverted`
		// when this fail , chain client should skip the outbound and move on to the next. The network will reschedule the outbound
		// after 300 blocks
		c.logger.Err(err).Msg("fail to estimate gas")
		return nil, nil
	}

	gasOut := big.NewInt(0)
	for _, coin := range txOutItem.MaxGas {
		gasOut.Add(gasOut, c.convertThorchainAmountToWei(coin.Amount.BigInt()))
	}
	totalGas := big.NewInt(int64(estimatedGas) * gasRate.Int64())
	if avaxValue.Uint64() > 0 {
		// when the estimated gas is larger than the MaxGas that is allowed to be used
		// adjust the gas price to reflect that , so not breach the MaxGas restriction
		// This might cause the tx to delay
		if totalGas.Cmp(gasOut) == 1 {
			// for Yggdrasil return , the total gas will always larger than gasOut , as we don't specify MaxGas
			if memo.GetType() == mem.TxYggdrasilReturn {
				if hasRouterUpdated {
					// when we are doing smart contract upgrade , we inflate the estimate gas by 1.5 , to give it more room with gas
					estimatedGas = estimatedGas * 3 / 2
					totalGas = big.NewInt(int64(estimatedGas) * gasRate.Int64())
				}
				// yggdrasil return fund
				gap := totalGas.Sub(totalGas, gasOut)
				c.logger.Info().Str("gas needed", gap.String()).Msg("yggdrasil returning funds")
				avaxValue = avaxValue.Sub(avaxValue, gap)
			} else {
				// At this point, if this is is to an aggregator (which should be white-listed), allow the maximum gas.
				if txOutItem.Aggregator == "" {
					gasRate = gasOut.Div(gasOut, big.NewInt(int64(estimatedGas)))
					c.logger.Info().Msgf("based on estimated gas unit (%d) , total gas will be %s, which is more than %s, so adjust gas rate to %s", estimatedGas, totalGas.String(), gasOut.String(), gasRate.String())
				} else {
					if estimatedGas > maxGasLimit {
						// the estimated gas unit is more than the maximum , so bring down the gas rate
						maxGasWei := big.NewInt(1).Mul(big.NewInt(maxGasLimit), gasRate)
						gasRate = big.NewInt(1).Div(maxGasWei, big.NewInt(int64(estimatedGas)))
					} else {
						estimatedGas = maxGasLimit // pay the maximum
					}
				}
			}
		} else {
			// override estimate gas with the max
			estimatedGas = big.NewInt(0).Div(gasOut, gasRate).Uint64()
			c.logger.Info().Str("memo", txOutItem.Memo).Uint64("estimatedGas", estimatedGas).Int64("gasRate", gasRate.Int64()).Msg("override estimate gas with max")
		}
		createdTx = etypes.NewTransaction(nonce, ecommon.HexToAddress(contractAddr.String()), avaxValue, estimatedGas, gasRate, txData)
	} else {
		if estimatedGas > maxGasLimit {
			// the estimated gas unit is more than the maximum , so bring down the gas rate
			maxGasWei := big.NewInt(1).Mul(big.NewInt(maxGasLimit), gasRate)
			gasRate = big.NewInt(1).Div(maxGasWei, big.NewInt(int64(estimatedGas)))
		}
		createdTx = etypes.NewTransaction(nonce, ecommon.HexToAddress(contractAddr.String()), avaxValue, estimatedGas, gasRate, txData)
	}

	return createdTx, nil
}

/* Sign and Broadcast */

// SignTx signs the the given TxArrayItem
func (c *AvalancheClient) SignTx(tx stypes.TxOutItem, height int64) ([]byte, error) {
	if !tx.Chain.Equals(common.AVAXChain) {
		return nil, fmt.Errorf("chain %s is not support by AVAX chain client", tx.Chain)
	}

	if c.signerCacheManager.HasSigned(tx.CacheHash()) {
		c.logger.Info().Interface("tx", tx).Msg("transaction signed before, ignore")
		return nil, nil
	}

	if tx.ToAddress.IsEmpty() {
		return nil, fmt.Errorf("to address is empty")
	}
	if tx.VaultPubKey.IsEmpty() {
		return nil, fmt.Errorf("vault public key is empty")
	}

	memo, err := mem.ParseMemo(common.LatestVersion, tx.Memo)
	if err != nil {
		return nil, fmt.Errorf("fail to parse memo(%s):%w", tx.Memo, err)
	}

	if memo.IsInbound() {
		return nil, fmt.Errorf("inbound memo should not be used for outbound tx")
	}

	if len(tx.Memo) == 0 {
		return nil, fmt.Errorf("can't sign tx when it doesn't have memo")
	}

	outboundTx, err := c.buildOutboundTx(tx, memo)
	if err != nil {
		c.logger.Err(err).Msg("Failed to build outbound tx")
		return nil, err
	}

	rawTx, err := c.sign(outboundTx, tx.VaultPubKey, height, tx)
	if err != nil || len(rawTx) == 0 {
		return nil, fmt.Errorf("fail to sign message: %w", err)
	}

	return rawTx, nil
}

// sign is design to sign a given message with keysign party and keysign wrapper
func (c *AvalancheClient) sign(tx *etypes.Transaction, poolPubKey common.PubKey, height int64, txOutItem stypes.TxOutItem) ([]byte, error) {
	rawBytes, err := c.kw.Sign(tx, poolPubKey)
	if err == nil && rawBytes != nil {
		return rawBytes, nil
	}
	var keysignError tss.KeysignError
	if errors.As(err, &keysignError) {
		if len(keysignError.Blame.BlameNodes) == 0 {
			// TSS doesn't know which node to blame
			return nil, fmt.Errorf("fail to sign tx: %w", err)
		}
		// key sign error forward the keysign blame to thorchain
		txID, errPostKeysignFail := c.bridge.PostKeysignFailure(keysignError.Blame, height, txOutItem.Memo, txOutItem.Coins, txOutItem.VaultPubKey)
		if errPostKeysignFail != nil {
			return nil, multierror.Append(err, errPostKeysignFail)
		}
		c.logger.Info().Str("tx_id", txID.String()).Msg("post keysign failure to thorchain")
	}
	return nil, fmt.Errorf("fail to sign tx: %w", err)
}

// BroadcastTx decodes tx using rlp and broadcasts to the AVAX C-Chain
func (c *AvalancheClient) BroadcastTx(txOutItem stypes.TxOutItem, hexTx []byte) (string, error) {
	tx := &etypes.Transaction{}
	if err := tx.UnmarshalJSON(hexTx); err != nil {
		return "", err
	}
	ctx, cancel := c.getContext()
	defer cancel()
	if err := c.ethClient.SendTransaction(ctx, tx); err != nil {
		c.logger.Error().Stringer("txid", tx.Hash()).Err(err).Msg("failed to send transaction")
		return "", nil
	}
	txID := tx.Hash().String()
	c.logger.Info().Str("memo", txOutItem.Memo).Str("hash", txID).Msg("broadcast tx to AVAX C-Chain")

	if err := c.signerCacheManager.SetSigned(txOutItem.CacheHash(), txID); err != nil {
		c.logger.Err(err).Interface("txOutItem", txOutItem).Msg("fail to mark tx out item as signed")
	}

	blockHeight, err := c.bridge.GetBlockHeight()
	if err != nil {
		c.logger.Err(err).Msg("fail to get current THORChain block height")
		// at this point , the tx already broadcast successfully , don't return an error
		// otherwise will cause the same tx to retry
	} else if err := c.AddSignedTxItem(txID, blockHeight, txOutItem.VaultPubKey.String()); err != nil {
		c.logger.Err(err).Str("hash", txID).Msg("fail to add signed tx item")
	}

	return txID, nil
}

// GetConfirmationCount - AVAX C-Chain has instant finality, so return 0
func (c *AvalancheClient) GetConfirmationCount(txIn stypes.TxIn) int64 {
	return 0
}

// ConfirmationCountReady - AVAX C-Chain has instant finality, THORChain can accept the tx instantly
func (c *AvalancheClient) ConfirmationCountReady(txIn stypes.TxIn) bool {
	return true
}

// OnObservedTxIn gets called from observer when we have a valid observation
func (c *AvalancheClient) OnObservedTxIn(txIn stypes.TxInItem, blockHeight int64) {
	m, err := mem.ParseMemo(common.LatestVersion, txIn.Memo)
	if err != nil {
		// Debug log only as ParseMemo error is expected for THORName inbounds.
		c.logger.Debug().Err(err).Str("memo", txIn.Memo).Msg("fail to parse memo")
		return
	}
	if !m.IsOutbound() {
		return
	}
	if m.GetTxID().IsEmpty() {
		return
	}
	if err := c.signerCacheManager.SetSigned(txIn.CacheHash(c.GetChain(), m.GetTxID().String()), txIn.Tx); err != nil {
		c.logger.Err(err).Msg("fail to update signer cache")
	}
}

func (c *AvalancheClient) ReportSolvency(avaxBlockHeight int64) error {
	if !c.ShouldReportSolvency(avaxBlockHeight) {
		return nil
	}
	// when block scanner is not healthy , falling behind , we don't report solvency , unless the request is coming from
	// auto-unhalt solvency runner
	if !c.IsBlockScannerHealthy() && avaxBlockHeight == c.avaxScanner.currentBlockHeight {
		return nil
	}
	asgardVaults, err := c.bridge.GetAsgards()
	if err != nil {
		return fmt.Errorf("fail to get asgards,err: %w", err)
	}
	for _, asgard := range asgardVaults {
		acct, err := c.GetAccount(asgard.PubKey, new(big.Int).SetInt64(avaxBlockHeight))
		if err != nil {
			c.logger.Err(err).Msg("fail to get account balance")
			continue
		}
		if runners.IsVaultSolvent(acct, asgard, cosmos.NewUint(3*MaxContractGas*c.avaxScanner.lastReportedGasPrice)) && c.IsBlockScannerHealthy() {
			// when vault is solvent, don't need to report solvency
			// when block scanner is not healthy , usually that means the chain is halted, in that scenario , we continue to report solvency
			continue
		}
		c.logger.Info().Str("asgard pubkey", asgard.PubKey.String()).Interface("coins", acct.Coins).Msg("Reporting solvency")
		select {
		case c.globalSolvencyQueue <- stypes.Solvency{
			Height: avaxBlockHeight,
			Chain:  common.AVAXChain,
			PubKey: asgard.PubKey,
			Coins:  acct.Coins,
		}:
		case <-time.After(constants.ThorchainBlockTime):
			c.logger.Info().Msg("fail to send solvency info to THORChain, timeout")
		}
	}
	c.lastSolvencyCheckHeight = avaxBlockHeight
	return nil
}

// ShouldReportSolvency with given block height, should chain client report Solvency to THORNode?
// AVAX C-Chain blocktime is around 2 seconds
func (c *AvalancheClient) ShouldReportSolvency(height int64) bool {
	return height%100 == 0
}
