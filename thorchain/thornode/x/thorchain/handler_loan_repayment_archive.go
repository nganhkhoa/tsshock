package thorchain

import (
	"fmt"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
)

func (h LoanRepaymentHandler) handleV107(ctx cosmos.Context, msg MsgLoanRepayment) error {
	// inject txid into the context if unset
	var err error
	ctx, err = storeContextTxID(ctx, constants.CtxLoanTxID)
	if err != nil {
		return err
	}

	// if the inbound asset is TOR, then lets repay the loan. If not, lets
	// swap first and try again later
	if msg.Coin.Asset.Equals(common.TOR) {
		return h.repayV107(ctx, msg)
	} else {
		return h.swapV107(ctx, msg)
	}
}

func (h LoanRepaymentHandler) repayV107(ctx cosmos.Context, msg MsgLoanRepayment) error {
	// collect data
	lendAddr, err := h.mgr.Keeper().GetModuleAddress(LendingName)
	if err != nil {
		ctx.Logger().Error("fail to get lending address", "error", err)
		return err
	}
	loan, err := h.mgr.Keeper().GetLoan(ctx, msg.CollateralAsset, msg.Owner)
	if err != nil {
		ctx.Logger().Error("fail to get loan", "error", err)
		return err
	}
	totalCollateral, err := h.mgr.Keeper().GetTotalCollateral(ctx, msg.CollateralAsset)
	if err != nil {
		return err
	}

	redeem := common.GetSafeShare(msg.Coin.Amount, loan.Debt(), loan.Collateral())
	if redeem.IsZero() {
		return fmt.Errorf("redeem cannot be zero")
	}

	// update Loan record
	loan.DebtDown = loan.DebtDown.Add(msg.Coin.Amount)
	loan.CollateralDown = loan.CollateralDown.Add(redeem)
	loan.LastRepayHeight = ctx.BlockHeight()

	// burn TOR coins
	if err := h.mgr.Keeper().SendFromModuleToModule(ctx, LendingName, ModuleName, common.NewCoins(msg.Coin)); err != nil {
		ctx.Logger().Error("fail to move coins during loan repayment", "error", err)
		return err
	} else {
		err := h.mgr.Keeper().BurnFromModule(ctx, ModuleName, msg.Coin)
		if err != nil {
			ctx.Logger().Error("fail to burn coins during loan repayment", "error", err)
			return err
		}
	}

	txID, ok := ctx.Value(constants.CtxLoanTxID).(common.TxID)
	if !ok {
		return fmt.Errorf("fail to get txid")
	}

	// ensure TxID does NOT have a collision with another swap, this could
	// happen if the user submits two identical loan requests in the same
	// block
	if ok := h.mgr.Keeper().HasSwapQueueItem(ctx, txID, 0); ok {
		return fmt.Errorf("txn hash conflict")
	}

	coins := common.NewCoins(common.NewCoin(msg.CollateralAsset.GetDerivedAsset(), redeem))

	// transfer derived asset from the lending to asgard before swap to L1 collateral
	err = h.mgr.Keeper().SendFromModuleToModule(ctx, LendingName, AsgardName, coins)
	if err != nil {
		ctx.Logger().Error("fail to send from lending to asgard", "error", err)
		return err
	}

	fakeGas := common.NewCoin(msg.Coin.Asset, cosmos.OneUint())
	tx := common.NewTx(txID, lendAddr, lendAddr, coins, common.Gas{fakeGas}, "noop")
	swapMsg := NewMsgSwap(tx, msg.CollateralAsset, msg.Owner, cosmos.ZeroUint(), common.NoAddress, cosmos.ZeroUint(), "", "", nil, 0, msg.Signer)
	if err := h.mgr.Keeper().SetSwapQueueItem(ctx, *swapMsg, 0); err != nil {
		ctx.Logger().Error("fail to add swap to queue", "error", err)
		return err
	}

	// update kvstore
	h.mgr.Keeper().SetLoan(ctx, loan)
	h.mgr.Keeper().SetTotalCollateral(ctx, msg.CollateralAsset, common.SafeSub(totalCollateral, redeem))

	// emit events and metrics
	evt := NewEventLoanRepayment(redeem, msg.Coin.Amount, msg.CollateralAsset, msg.Owner)
	if err := h.mgr.EventMgr().EmitEvent(ctx, evt); nil != err {
		ctx.Logger().Error("fail to emit loan open event", "error", err)
	}

	return nil
}
