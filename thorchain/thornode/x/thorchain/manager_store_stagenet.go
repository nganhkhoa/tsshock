//go:build stagenet
// +build stagenet

package thorchain

import (
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
)

func migrateStoreV86(ctx cosmos.Context, mgr Manager) {}
func migrateStoreV88(ctx cosmos.Context, mgr Manager) {}

func migrateStoreV102(ctx cosmos.Context, mgr *Mgrs) {
	defer func() {
		if err := recover(); err != nil {
			ctx.Logger().Error("fail to migrate store to v102", "error", err)
		}
	}()

	// STAGENET TESTING
	// Refund a 10 RUNE swap out tx that was eaten due to bad external asset matching:
	// https://stagenet-thornode.ninerealms.com/thorchain/tx/5FAAE55F9043580A1387E66CB9D749A5D262CED5F6F654640918149F71D8E4D6/signers

	// The RUNE was swapped to ETH, but the outbound swap out was dropped by Bifrost. This means RUNE was added, ETH was removed from
	// the pool. This must be reversed and the RUNE sent back to the user.
	// So:
	// 1. Credit the total ETH amount back the pool, this ETH is already in the pool since the outbound was dropped.
	// 2. Deduct the RUNE balance from the ETH pool, this will be sent back to the user.
	// 3. Send the user RUNE from Asgard.
	//
	// Note: the Asgard vault does not need to be credited the ETH since the outbound was never sent, thus never observed (which
	// is where Vault funds are subtracted)

	firstSwapOut := DroppedSwapOutTx{
		inboundHash: "5FAAE55F9043580A1387E66CB9D749A5D262CED5F6F654640918149F71D8E4D6",
		gasAsset:    common.ETHAsset,
	}

	err := refundDroppedSwapOutFromRUNE(ctx, mgr, firstSwapOut)
	if err != nil {
		ctx.Logger().Error("fail to migrate store to v102 refund failed", "error", err)
	}
}

// no op
func migrateStoreV103(ctx cosmos.Context, mgr *Mgrs) {}

// no op
func migrateStoreV106(ctx cosmos.Context, mgr *Mgrs) {}
