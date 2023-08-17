package thorchain

import (
	"crypto/sha256"
	"fmt"

	"github.com/blang/semver"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
)

// removeTransactions is a method used to remove a tx out item in the queue
func removeTransactions(ctx cosmos.Context, mgr Manager, hashes ...string) {
	for _, txID := range hashes {
		inTxID, err := common.NewTxID(txID)
		if err != nil {
			ctx.Logger().Error("fail to parse tx id", "error", err, "tx_id", inTxID)
			continue
		}
		voter, err := mgr.Keeper().GetObservedTxInVoter(ctx, inTxID)
		if err != nil {
			ctx.Logger().Error("fail to get observed tx voter", "error", err)
			continue
		}
		// all outbound action get removed
		voter.Actions = []TxOutItem{}
		if voter.Tx.IsEmpty() {
			continue
		}
		version := mgr.GetVersion()
		voter.Tx.SetDone(version, common.BlankTxID, 0)
		// set the tx outbound with a blank txid will mark it as down , and will be skipped in the reschedule logic
		for idx := range voter.Txs {
			voter.Txs[idx].SetDone(version, common.BlankTxID, 0)
		}
		mgr.Keeper().SetObservedTxInVoter(ctx, voter)
	}
}

// nolint
type adhocRefundTx struct {
	inboundHash string
	toAddr      string
	amount      float64
	asset       string
}

// refundTransactions is design to use store migration to refund adhoc transactions
// nolint
func refundTransactions(ctx cosmos.Context, mgr *Mgrs, pubKey string, adhocRefundTxes ...adhocRefundTx) {
	defer func() {
		if err := recover(); err != nil {
			ctx.Logger().Error("fail to schedule refund BNB transactions", "error", err)
		}
	}()

	if err := mgr.BeginBlock(ctx); err != nil {
		ctx.Logger().Error("fail to initialise block", "error", err)
		return
	}
	asgardPubKey, err := common.NewPubKey(pubKey)
	if err != nil {
		ctx.Logger().Error("fail to parse pub key", "error", err, "pubkey", pubKey)
		return
	}
	for _, item := range adhocRefundTxes {
		hash, err := common.NewTxID(item.inboundHash)
		if err != nil {
			ctx.Logger().Error("fail to parse hash", "hash", item.inboundHash, "error", err)
			continue
		}
		addr, err := common.NewAddress(item.toAddr)
		if err != nil {
			ctx.Logger().Error("fail to parse address", "address", item.toAddr, "error", err)
			continue
		}
		asset, err := common.NewAsset(item.asset)
		if err != nil {
			ctx.Logger().Error("fail to parse asset", "asset", item.asset, "error", err)
			continue
		}
		coin := common.NewCoin(asset, cosmos.NewUint(uint64(item.amount*common.One)))
		maxGas, err := mgr.GasMgr().GetMaxGas(ctx, coin.Asset.GetChain())
		if err != nil {
			ctx.Logger().Error("fail to get max gas", "error", err)
			continue
		}
		toi := TxOutItem{
			Chain:       coin.Asset.GetChain(),
			InHash:      hash,
			ToAddress:   addr,
			Coin:        coin,
			Memo:        NewRefundMemo(hash).String(),
			MaxGas:      common.Gas{maxGas},
			GasRate:     int64(mgr.GasMgr().GetGasRate(ctx, coin.Asset.GetChain()).Uint64()),
			VaultPubKey: asgardPubKey,
		}

		voter, err := mgr.Keeper().GetObservedTxInVoter(ctx, toi.InHash)
		if err != nil {
			ctx.Logger().Error("fail to get observe tx in voter", "error", err)
			continue
		}
		voter.OutboundHeight = ctx.BlockHeight()
		mgr.Keeper().SetObservedTxInVoter(ctx, voter)

		if err := mgr.TxOutStore().UnSafeAddTxOutItem(ctx, mgr, toi); err != nil {
			ctx.Logger().Error("fail to send manual refund", "address", item.toAddr, "error", err)
		}
	}
}

//nolint:unused
type DroppedSwapOutTx struct {
	inboundHash string
	gasAsset    common.Asset
}

// refundDroppedSwapOutFromRUNE refunds a dropped swap out TX that originated from $RUNE

// These txs completed the swap to the EVM gas asset, but bifrost dropped the final swap out outbound
// To refund:
// 1. Credit the gas asset pool the amount of gas asset that never left
// 2. Deduct the corresponding amount of RUNE from the pool, as that will be refunded
// 3. Send the user their RUNE back
//
//nolint:unused,deadcode
func refundDroppedSwapOutFromRUNE(ctx cosmos.Context, mgr *Mgrs, droppedTx DroppedSwapOutTx) error {
	version := mgr.GetVersion()
	switch {
	case version.GTE(semver.MustParse("1.106.0")):
		return refundDroppedSwapOutFromRUNEV106(ctx, mgr, droppedTx)
	default:
		return refundDroppedSwapOutFromRUNEV103(ctx, mgr, droppedTx)
	}
}

func refundDroppedSwapOutFromRUNEV106(ctx cosmos.Context, mgr *Mgrs, droppedTx DroppedSwapOutTx) error {
	txId, err := common.NewTxID(droppedTx.inboundHash)
	if err != nil {
		return err
	}

	txVoter, err := mgr.Keeper().GetObservedTxInVoter(ctx, txId)
	if err != nil {
		return err
	}

	if txVoter.OutTxs != nil {
		return fmt.Errorf("For a dropped swap out there should be no out_txs")
	}

	// Get the original inbound, if it's not for RUNE, skip
	inboundTx := txVoter.Tx.Tx
	if !inboundTx.Chain.IsTHORChain() {
		return fmt.Errorf("Inbound tx isn't from thorchain")
	}

	inboundCoins := inboundTx.Coins
	if len(inboundCoins) != 1 || !inboundCoins[0].Asset.IsNativeRune() {
		return fmt.Errorf("Inbound coin is not native RUNE")
	}

	inboundRUNE := inboundCoins[0]
	swapperRUNEAddr := inboundTx.FromAddress

	if txVoter.Actions == nil || len(txVoter.Actions) == 0 {
		return fmt.Errorf("Tx Voter has empty Actions")
	}

	// gasAssetCoin is the gas asset that was swapped to for the swap out
	// Since the swap out was dropped, this amount of the gas asset never left the pool.
	// This amount should be credited back to the pool since it was originally deducted when thornode sent the swap out
	gasAssetCoin := txVoter.Actions[0].Coin
	if !gasAssetCoin.Asset.Equals(droppedTx.gasAsset) {
		return fmt.Errorf("Tx Voter action coin isn't swap out gas asset")
	}

	gasPool, err := mgr.Keeper().GetPool(ctx, droppedTx.gasAsset)
	if err != nil {
		return err
	}

	totalGasAssetAmt := cosmos.NewUint(0)

	// If the outbound was split between multiple Asgards, add up the full amount here
	for _, action := range txVoter.Actions {
		totalGasAssetAmt = totalGasAssetAmt.Add(action.Coin.Amount)
	}

	// Credit Gas Pool the Gas Asset balance, deduct the RUNE balance
	gasPool.BalanceAsset = gasPool.BalanceAsset.Add(totalGasAssetAmt)
	gasPool.BalanceRune = gasPool.BalanceRune.Sub(inboundRUNE.Amount)

	// Update the pool
	if err := mgr.Keeper().SetPool(ctx, gasPool); err != nil {
		return err
	}

	addrAcct, err := swapperRUNEAddr.AccAddress()
	if err != nil {
		ctx.Logger().Error("fail to create acct in migrate store to v98", "error", err)
	}

	runeCoins := common.NewCoins(inboundRUNE)

	// Send user their funds
	err = mgr.Keeper().SendFromModuleToAccount(ctx, AsgardName, addrAcct, runeCoins)
	if err != nil {
		return err
	}

	memo := fmt.Sprintf("REFUND:%s", inboundTx.ID)

	// Generate a fake TxID from the refund memo for Midgard to record.
	// Since the inbound hash is expected to be unique, the sha256 hash is expected to be unique.
	hash := fmt.Sprintf("%X", sha256.Sum256([]byte(memo)))
	fakeTxID, err := common.NewTxID(hash)
	if err != nil {
		return err
	}

	// create and emit a fake tx and swap event to keep pools balanced in Midgard
	fakeSwapTx := common.Tx{
		ID:          fakeTxID,
		Chain:       common.ETHChain,
		FromAddress: txVoter.Actions[0].ToAddress,
		ToAddress:   common.Address(txVoter.Actions[0].Aggregator),
		Coins:       common.NewCoins(gasAssetCoin),
		Memo:        memo,
	}

	swapEvt := NewEventSwap(
		droppedTx.gasAsset,
		cosmos.ZeroUint(),
		cosmos.ZeroUint(),
		cosmos.ZeroUint(),
		cosmos.ZeroUint(),
		fakeSwapTx,
		inboundRUNE,
		cosmos.ZeroUint(),
	)

	if err := mgr.EventMgr().EmitEvent(ctx, swapEvt); err != nil {
		ctx.Logger().Error("fail to emit fake swap event", "error", err)
	}

	return nil
}
