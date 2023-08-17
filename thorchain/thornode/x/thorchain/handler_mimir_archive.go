package thorchain

import (
	"fmt"
	"strconv"
	"strings"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
)

func (h MimirHandler) validateV95(ctx cosmos.Context, msg MsgMimir) error {
	if err := msg.ValidateBasic(); err != nil {
		return err
	}
	if !mimirValidKeyV95(msg.Key) || len(msg.Key) > 64 {
		return cosmos.ErrUnknownRequest("invalid mimir key")
	}
	if !isAdmin(msg.Signer) && !isSignedByActiveNodeAccounts(ctx, h.mgr.Keeper(), msg.GetSigners()) {
		return cosmos.ErrUnauthorized(fmt.Sprintf("%s is not authorizaed", msg.Signer))
	}
	return nil
}

func (h MimirHandler) validateV78(ctx cosmos.Context, msg MsgMimir) error {
	if err := msg.ValidateBasic(); err != nil {
		return err
	}
	if !mimirValidKey(msg.Key) || len(msg.Key) > 64 {
		return cosmos.ErrUnknownRequest("invalid mimir key")
	}
	if !isAdmin(msg.Signer) && !isSignedByActiveNodeAccounts(ctx, h.mgr.Keeper(), msg.GetSigners()) {
		return cosmos.ErrUnauthorized(fmt.Sprintf("%s is not authorizaed", msg.Signer))
	}
	return nil
}

func (h MimirHandler) handleV87(ctx cosmos.Context, msg MsgMimir) error {
	if isAdmin(msg.Signer) {
		if msg.Value < 0 {
			_ = h.mgr.Keeper().DeleteMimir(ctx, msg.Key)
		} else {
			h.mgr.Keeper().SetMimir(ctx, msg.Key, msg.Value)
		}

		mimirEvent := NewEventSetMimir(strings.ToUpper(msg.Key), strconv.FormatInt(msg.Value, 10))
		if err := h.mgr.EventMgr().EmitEvent(ctx, mimirEvent); err != nil {
			ctx.Logger().Error("fail to emit set_mimir event", "error", err)
		}

	} else {
		nodeAccount, err := h.mgr.Keeper().GetNodeAccount(ctx, msg.Signer)
		if err != nil {
			ctx.Logger().Error("fail to get node account", "error", err, "address", msg.Signer.String())
			return cosmos.ErrUnauthorized(fmt.Sprintf("%s is not authorized", msg.Signer))
		}

		c, err := h.mgr.Keeper().GetMimir(ctx, constants.NativeTransactionFee.String())
		if err != nil || c < 0 {
			c = h.mgr.GetConstants().GetInt64Value(constants.NativeTransactionFee)
		}
		cost := cosmos.NewUint(uint64(c))
		nodeAccount.Bond = common.SafeSub(nodeAccount.Bond, cost)
		if err := h.mgr.Keeper().SetNodeAccount(ctx, nodeAccount); err != nil {
			ctx.Logger().Error("fail to save node account", "error", err)
			return fmt.Errorf("fail to save node account: %w", err)
		}

		// add 10 bond to reserve
		coin := common.NewCoin(common.RuneNative, cost)
		if !cost.IsZero() {
			if err := h.mgr.Keeper().SendFromModuleToModule(ctx, BondName, ReserveName, common.NewCoins(coin)); err != nil {
				ctx.Logger().Error("fail to transfer funds from bond to reserve", "error", err)
				return err
			}
		}

		if err := h.mgr.Keeper().SetNodeMimir(ctx, msg.Key, msg.Value, msg.Signer); err != nil {
			ctx.Logger().Error("fail to save node mimir", "error", err)
			return err
		}

		mimirEvent := NewEventSetNodeMimir(strings.ToUpper(msg.Key), strconv.FormatInt(msg.Value, 10), msg.Signer.String())
		if err := h.mgr.EventMgr().EmitEvent(ctx, mimirEvent); err != nil {
			ctx.Logger().Error("fail to emit set_node_mimir event", "error", err)
		}

		tx := common.Tx{}
		tx.ID = common.BlankTxID
		tx.ToAddress = common.Address(nodeAccount.String())
		bondEvent := NewEventBond(cost, BondCost, tx)
		if err := h.mgr.EventMgr().EmitEvent(ctx, bondEvent); err != nil {
			ctx.Logger().Error("fail to emit bond event", "error", err)
		}
	}

	return nil
}

func (h MimirHandler) handleV81(ctx cosmos.Context, msg MsgMimir) error {
	if isAdmin(msg.Signer) {
		if msg.Value < 0 {
			_ = h.mgr.Keeper().DeleteMimir(ctx, msg.Key)
		} else {
			h.mgr.Keeper().SetMimir(ctx, msg.Key, msg.Value)
		}

		ctx.EventManager().EmitEvent(
			cosmos.NewEvent("set_mimir",
				cosmos.NewAttribute("key", msg.Key),
				cosmos.NewAttribute("value", strconv.FormatInt(msg.Value, 10))))
	} else {
		nodeAccount, err := h.mgr.Keeper().GetNodeAccount(ctx, msg.Signer)
		if err != nil {
			ctx.Logger().Error("fail to get node account", "error", err, "address", msg.Signer.String())
			return cosmos.ErrUnauthorized(fmt.Sprintf("%s is not authorized", msg.Signer))
		}

		c, err := h.mgr.Keeper().GetMimir(ctx, constants.NativeTransactionFee.String())
		if err != nil || c < 0 {
			c = h.mgr.GetConstants().GetInt64Value(constants.NativeTransactionFee)
		}
		cost := cosmos.NewUint(uint64(c))
		nodeAccount.Bond = common.SafeSub(nodeAccount.Bond, cost)
		if err := h.mgr.Keeper().SetNodeAccount(ctx, nodeAccount); err != nil {
			ctx.Logger().Error("fail to save node account", "error", err)
			return fmt.Errorf("fail to save node account: %w", err)
		}

		// add 10 bond to reserve
		coin := common.NewCoin(common.RuneNative, cost)
		if !cost.IsZero() {
			if err := h.mgr.Keeper().SendFromModuleToModule(ctx, BondName, ReserveName, common.NewCoins(coin)); err != nil {
				ctx.Logger().Error("fail to transfer funds from bond to reserve", "error", err)
				return err
			}
		}

		if err := h.mgr.Keeper().SetNodeMimir(ctx, msg.Key, msg.Value, msg.Signer); err != nil {
			ctx.Logger().Error("fail to save node mimir", "error", err)
			return err
		}

		ctx.EventManager().EmitEvent(
			cosmos.NewEvent("set_node_mimir",
				cosmos.NewAttribute("key", strings.ToUpper(msg.Key)),
				cosmos.NewAttribute("value", strconv.FormatInt(msg.Value, 10)),
				cosmos.NewAttribute("address", msg.Signer.String())))

		tx := common.Tx{}
		tx.ID = common.BlankTxID
		tx.ToAddress = common.Address(nodeAccount.String())
		bondEvent := NewEventBond(cost, BondCost, tx)
		if err := h.mgr.EventMgr().EmitEvent(ctx, bondEvent); err != nil {
			ctx.Logger().Error("fail to emit bond event", "error", err)
		}
	}

	return nil
}
