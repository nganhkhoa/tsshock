package avalanche

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	ecommon "github.com/ethereum/go-ethereum/common"
	etypes "github.com/ethereum/go-ethereum/core/types"

	evmtypes "gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/shared/evm/types"
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/constants"
)

// This is the number of THORChain blocks to wait before
// re-broadcasting a stuck tx with more gas. 150 was chosen
// because the signing period for outbounds is 300 blocks.
// After 300 blocks the tx will be re-assigned to a different vault, so
// we want to try to push the tx through before that
const TxWaitBlocks = 150

// This process watches outbound TXs on AVAX to ensure they go
// through before being re-assigned to a different vault. C-Chain txs
// can get stuck because of a sudden increase in gas prices, so this
// process will re-broadcast the same tx with more gas to push it through
func (c *AvalancheClient) unstuck() {
	c.logger.Info().Msg("start AVAX chain unstuck process")
	defer c.logger.Info().Msg("stop AVAX chain unstuck process")
	defer c.wg.Done()
	for {
		select {
		case <-c.stopchan:
			// time to exit
			return
		case <-time.After(constants.ThorchainBlockTime):
			c.unstuckAction()
		}
	}
}

func (c *AvalancheClient) unstuckAction() {
	height, err := c.bridge.GetBlockHeight()
	if err != nil {
		c.logger.Err(err).Msg("fail to get THORChain block height")
		return
	}
	signedTxItems, err := c.avaxScanner.blockMetaAccessor.GetSignedTxItems()
	if err != nil {
		c.logger.Err(err).Msg("fail to get all signed tx items")
		return
	}
	for _, item := range signedTxItems {
		// this should not possible, but just skip it
		if item.Height > height {
			c.logger.Warn().Msg("signed outbound height greater than current thorchain height")
			continue
		}

		if (height - item.Height) < TxWaitBlocks {
			// not time yet , continue to wait for this tx to commit
			continue
		}
		if err := c.unstuckTx(item.VaultPubKey, item.Hash); err != nil {
			c.logger.Err(err).Str("tx hash", item.Hash).Str("vault", item.VaultPubKey).Msg("fail to unstuck tx")
			continue
		}
		// remove it
		if err := c.avaxScanner.blockMetaAccessor.RemoveSignedTxItem(item.Hash); err != nil {
			c.logger.Err(err).Str("tx hash", item.Hash).Str("vault", item.VaultPubKey).Msg("fail to remove signed tx item")
		}
	}
}

// unstuckTx is the method used to unstuck AVAX address
// when unstuckTx return an err , then the same hash should retry otherwise it can be removed
func (c *AvalancheClient) unstuckTx(vaultPubKey, hash string) error {
	ctx, cancel := c.getContext()
	defer cancel()
	tx, pending, err := c.ethClient.TransactionByHash(ctx, ecommon.HexToHash(hash))
	if err != nil {
		if errors.Is(err, ethereum.NotFound) {
			c.logger.Err(err).Str("tx hash", hash).Msg("Transaction doesn't exist on AVAX chain anymore")
			return nil
		}
		return fmt.Errorf("fail to get transaction by hash:%s, error:: %w", hash, err)
	}
	// the transaction is not pending any more
	if !pending {
		c.logger.Info().Str("tx hash", hash).Msg("transaction already committed on block , don't need to unstuck, remove it")
		return nil
	}

	pubKey, err := common.NewPubKey(vaultPubKey)
	if err != nil {
		c.logger.Err(err).Str("pubkey", vaultPubKey).Msg("public key is invalid")
		// this should not happen , and if it does , there is no point to try it again , just remove it
		return nil
	}
	address, err := pubKey.GetAddress(common.AVAXChain)
	if err != nil {
		c.logger.Err(err).Msg("fail to get AVAX address")
		return nil
	}

	c.logger.Info().Str("tx hash", hash).Uint64("nonce", tx.Nonce()).Msg("cancel tx hash with nonce")
	// double the current suggest gas price
	currentGasRate := big.NewInt(1).Mul(c.GetGasPrice(), big.NewInt(2))
	// inflate the originGasPrice by 10% as per AVAX chain, the transaction to cancel an existing tx in the mempool
	// need to pay at least 10% more than the original price, otherwise it will not allow it.
	// the error will be "replacement transaction underpriced"
	// this is the way to get 110% of the original gas price
	originGasPrice := tx.GasPrice()
	inflatedOriginalGasPrice := big.NewInt(1).Div(big.NewInt(1).Mul(tx.GasPrice(), big.NewInt(11)), big.NewInt(10))
	if inflatedOriginalGasPrice.Cmp(currentGasRate) > 0 {
		currentGasRate = big.NewInt(1).Mul(originGasPrice, big.NewInt(2))
	}
	canceltx := etypes.NewTransaction(tx.Nonce(), ecommon.HexToAddress(address.String()), big.NewInt(0), MaxContractGas, currentGasRate, nil)
	rawBytes, err := c.kw.Sign(canceltx, pubKey)
	if err != nil {
		return fmt.Errorf("fail to sign tx for cancelling with nonce: %d,err: %w", tx.Nonce(), err)
	}
	broadcastTx := &etypes.Transaction{}
	if err := broadcastTx.UnmarshalJSON(rawBytes); err != nil {
		return fmt.Errorf("fail to unmarshal tx, err: %w", err)
	}
	ctx, cancel = c.getContext()
	defer cancel()
	err = c.avaxScanner.ethClient.SendTransaction(ctx, broadcastTx)
	if !isAcceptableError(err) {
		return fmt.Errorf("fail to broadcast the cancel transaction, hash:%s , err: %w", hash, err)
	}

	c.logger.Info().Str("old tx hash", hash).Uint64("nonce", tx.Nonce()).Str("new tx hash", broadcastTx.Hash().String()).Msg("broadcast new tx, old tx cancelled")
	return nil
}

// AddSignedTxItem add the transaction to key value store
func (c *AvalancheClient) AddSignedTxItem(hash string, height int64, vaultPubKey string) error {
	return c.avaxScanner.blockMetaAccessor.AddSignedTxItem(evmtypes.SignedTxItem{
		Hash:        hash,
		Height:      height,
		VaultPubKey: vaultPubKey,
	})
}
