package thorchain

import (
	. "gopkg.in/check.v1"

	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/constants"
	"gitlab.com/thorchain/thornode/x/thorchain/types"
)

type TxOutStoreV98Suite struct{}

var _ = Suite(&TxOutStoreV98Suite{})

func (s TxOutStoreV98Suite) TestAddGasFees(c *C) {
	ctx, mgr := setupManagerForTest(c)
	tx := GetRandomObservedTx()

	version := GetCurrentVersion()
	constAccessor := constants.GetConstantValues(version)
	mgr.gasMgr = newGasMgrV81(constAccessor, mgr.Keeper())
	err := addGasFees(ctx, mgr, tx)
	c.Assert(err, IsNil)
	c.Assert(mgr.GasMgr().GetGas(), HasLen, 1)
}

func (s TxOutStoreV98Suite) TestEndBlock(c *C) {
	w := getHandlerTestWrapper(c, 1, true, true)
	txOutStore := newTxOutStorageV98(w.keeper, w.mgr.GetConstants(), w.mgr.EventMgr(), w.mgr.GasMgr())

	item := TxOutItem{
		Chain:     common.BNBChain,
		ToAddress: GetRandomBNBAddress(),
		InHash:    GetRandomTxHash(),
		Coin:      common.NewCoin(common.BNBAsset, cosmos.NewUint(20*common.One)),
	}
	err := txOutStore.UnSafeAddTxOutItem(w.ctx, w.mgr, item)
	c.Assert(err, IsNil)

	c.Assert(txOutStore.EndBlock(w.ctx, w.mgr), IsNil)

	items, err := txOutStore.GetOutboundItems(w.ctx)
	c.Assert(err, IsNil)
	c.Assert(items, HasLen, 1)
	c.Check(items[0].GasRate, Equals, int64(56250))
	c.Assert(items[0].MaxGas, HasLen, 1)
	c.Check(items[0].MaxGas[0].Asset.Equals(common.BNBAsset), Equals, true)
	c.Check(items[0].MaxGas[0].Amount.Uint64(), Equals, uint64(37500))
}

func (s TxOutStoreV98Suite) TestAddOutTxItem(c *C) {
	w := getHandlerTestWrapper(c, 1, true, true)
	vault := GetRandomVault()
	vault.Coins = common.Coins{
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(10000*common.One)),
		common.NewCoin(common.BNBAsset, cosmos.NewUint(10000*common.One)),
	}
	c.Assert(w.keeper.SetVault(w.ctx, vault), IsNil)

	acc1 := GetRandomValidatorNode(NodeActive)
	acc2 := GetRandomValidatorNode(NodeActive)
	acc3 := GetRandomValidatorNode(NodeActive)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc1), IsNil)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc2), IsNil)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc3), IsNil)

	ygg := NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc1.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(40*common.One)),
			common.NewCoin(common.BCHAsset, cosmos.NewUint(40*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	ygg = NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc2.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(50*common.One)),
			common.NewCoin(common.BCHAsset, cosmos.NewUint(40*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	ygg = NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc3.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(100*common.One)),
			common.NewCoin(common.BCHAsset, cosmos.NewUint(40*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	// Create voter
	inTxID := GetRandomTxHash()
	voter := NewObservedTxVoter(inTxID, ObservedTxs{
		ObservedTx{
			Tx:             GetRandomTx(),
			Status:         types.Status_incomplete,
			BlockHeight:    1,
			Signers:        []string{w.activeNodeAccount.NodeAddress.String(), acc1.NodeAddress.String(), acc2.NodeAddress.String()},
			KeysignMs:      0,
			FinaliseHeight: 1,
		},
	})
	w.keeper.SetObservedTxInVoter(w.ctx, voter)

	// Should get acc2. Acc3 hasn't signed and acc2 is the highest value
	item := TxOutItem{
		Chain:     common.BNBChain,
		ToAddress: GetRandomBNBAddress(),
		InHash:    inTxID,
		Coin:      common.NewCoin(common.BNBAsset, cosmos.NewUint(20*common.One)),
	}
	txOutStore := newTxOutStorageV98(w.keeper, w.mgr.GetConstants(), w.mgr.EventMgr(), w.mgr.GasMgr())
	ok, err := txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
	c.Assert(err, IsNil)
	c.Assert(ok, Equals, true)
	msgs, err := txOutStore.GetOutboundItems(w.ctx)
	c.Assert(err, IsNil)
	c.Assert(msgs, HasLen, 1)
	c.Assert(msgs[0].VaultPubKey.String(), Equals, acc2.PubKeySet.Secp256k1.String())
	c.Assert(msgs[0].Coin.Amount.Equal(cosmos.NewUint(1999887500)), Equals, true, Commentf("%d", msgs[0].Coin.Amount.Uint64()))
	// Should get acc1. Acc3 hasn't signed and acc1 now has the highest amount
	// of coin.
	item = TxOutItem{
		Chain:     common.BNBChain,
		ToAddress: GetRandomBNBAddress(),
		InHash:    inTxID,
		Coin:      common.NewCoin(common.BNBAsset, cosmos.NewUint(20*common.One)),
	}
	txOutStore.ClearOutboundItems(w.ctx)
	success, err := txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
	c.Assert(success, Equals, true)
	c.Assert(err, IsNil)
	msgs, err = txOutStore.GetOutboundItems(w.ctx)
	c.Assert(err, IsNil)
	c.Assert(msgs, HasLen, 1)
	c.Assert(msgs[0].VaultPubKey.String(), Equals, acc2.PubKeySet.Secp256k1.String())

	item = TxOutItem{
		Chain:     common.BNBChain,
		ToAddress: GetRandomBNBAddress(),
		InHash:    inTxID,
		Coin:      common.NewCoin(common.BNBAsset, cosmos.NewUint(1000*common.One)),
	}
	txOutStore.ClearOutboundItems(w.ctx)
	success, err = txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
	c.Assert(err, IsNil)
	c.Assert(success, Equals, true)
	msgs, err = txOutStore.GetOutboundItems(w.ctx)
	c.Assert(err, IsNil)
	c.Assert(msgs, HasLen, 1)
	c.Check(msgs[0].VaultPubKey.String(), Equals, vault.PubKey.String())

	item = TxOutItem{
		Chain:     common.BCHChain,
		ToAddress: "1EFJFJm7Y9mTVsCBXA9PKuRuzjgrdBe4rR",
		InHash:    inTxID,
		Coin:      common.NewCoin(common.BCHAsset, cosmos.NewUint(20*common.One)),
		MaxGas: common.Gas{
			common.NewCoin(common.BCHAsset, cosmos.NewUint(10000)),
		},
	}
	txOutStore.ClearOutboundItems(w.ctx)
	result, err := txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
	c.Assert(result, Equals, true)
	c.Assert(err, IsNil)
	msgs, err = txOutStore.GetOutboundItems(w.ctx)
	c.Assert(err, IsNil)
	// this should be a mocknet address
	c.Assert(msgs[0].ToAddress.String(), Equals, "qzg5mkh7rkw3y8kw47l3rrnvhmenvctmd5yg6hxe64")

	// outbound originating from a pool should pay fee from asgard to reserve
	FundModule(c, w.ctx, w.keeper, AsgardName, 1000_00000000)
	testAndCheckModuleBalances(c, w.ctx, w.keeper,
		func() {
			item = TxOutItem{
				Chain:     common.THORChain,
				ToAddress: GetRandomRUNEAddress(),
				InHash:    inTxID,
				Coin:      common.NewCoin(common.RuneAsset(), cosmos.NewUint(1000*common.One)),
			}
			txOutStore.ClearOutboundItems(w.ctx)
			success, err = txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
			c.Assert(err, IsNil)
			c.Assert(success, Equals, true)
			msgs, err = txOutStore.GetOutboundItems(w.ctx)
			c.Assert(err, IsNil)
			c.Assert(msgs, HasLen, 0)
		},
		ModuleBalances{
			Asgard:  -1000_00000000,
			Reserve: 2000000,
		},
	)

	// outbound originating from bond should pay fee from bond to reserve
	FundModule(c, w.ctx, w.keeper, BondName, 1000_00000000)
	testAndCheckModuleBalances(c, w.ctx, w.keeper,
		func() {
			item = TxOutItem{
				ModuleName: BondName,
				Chain:      common.THORChain,
				ToAddress:  GetRandomRUNEAddress(),
				InHash:     inTxID,
				Coin:       common.NewCoin(common.RuneAsset(), cosmos.NewUint(1000*common.One)),
			}
			txOutStore.ClearOutboundItems(w.ctx)
			success, err = txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
			c.Assert(err, IsNil)
			c.Assert(success, Equals, true)
			msgs, err = txOutStore.GetOutboundItems(w.ctx)
			c.Assert(err, IsNil)
			c.Assert(msgs, HasLen, 0)
		},
		ModuleBalances{
			Bond:    -1000_00000000,
			Reserve: 2000000,
		},
	)

	// ensure that min out is respected
	success, err = txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.NewUint(9999999999*common.One))
	c.Check(success, Equals, false)
	c.Check(err, NotNil)
}

func (s TxOutStoreV98Suite) TestAddOutTxItem_OutboundHeightDoesNotGetOverride(c *C) {
	SetupConfigForTest()
	w := getHandlerTestWrapper(c, 1, true, true)
	vault := GetRandomVault()
	vault.Coins = common.Coins{
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(10000*common.One)),
		common.NewCoin(common.BNBAsset, cosmos.NewUint(10000*common.One)),
	}
	c.Assert(w.keeper.SetVault(w.ctx, vault), IsNil)

	acc1 := GetRandomValidatorNode(NodeActive)
	acc2 := GetRandomValidatorNode(NodeActive)
	acc3 := GetRandomValidatorNode(NodeActive)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc1), IsNil)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc2), IsNil)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc3), IsNil)

	ygg := NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc1.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(40*common.One)),
			common.NewCoin(common.BCHAsset, cosmos.NewUint(40*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	ygg = NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc2.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(50*common.One)),
			common.NewCoin(common.BCHAsset, cosmos.NewUint(40*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	ygg = NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc3.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(100*common.One)),
			common.NewCoin(common.BCHAsset, cosmos.NewUint(40*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)
	w.keeper.SetMimir(w.ctx, constants.MinTxOutVolumeThreshold.String(), 100000000000)
	w.keeper.SetMimir(w.ctx, constants.TxOutDelayRate.String(), 2500000000)
	w.keeper.SetMimir(w.ctx, constants.MaxTxOutOffset.String(), 720)
	// Create voter
	inTxID := GetRandomTxHash()
	voter := NewObservedTxVoter(inTxID, ObservedTxs{
		ObservedTx{
			Tx:             GetRandomTx(),
			Status:         types.Status_incomplete,
			BlockHeight:    1,
			Signers:        []string{w.activeNodeAccount.NodeAddress.String(), acc1.NodeAddress.String(), acc2.NodeAddress.String()},
			KeysignMs:      0,
			FinaliseHeight: 1,
		},
	})
	w.keeper.SetObservedTxInVoter(w.ctx, voter)

	// this should be sent via asgard
	item := TxOutItem{
		Chain:     common.BNBChain,
		ToAddress: GetRandomBNBAddress(),
		InHash:    inTxID,
		Coin:      common.NewCoin(common.BNBAsset, cosmos.NewUint(80*common.One)),
	}
	txOutStore := newTxOutStorageV98(w.keeper, w.mgr.GetConstants(), w.mgr.EventMgr(), w.mgr.GasMgr())
	ok, err := txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
	c.Assert(err, IsNil)
	c.Assert(ok, Equals, true)

	msgs, err := txOutStore.GetOutboundItems(w.ctx)
	c.Assert(err, IsNil)
	c.Assert(msgs, HasLen, 0)
	//  the outbound has been delayed
	newCtx := w.ctx.WithBlockHeight(4)
	msgs, err = txOutStore.GetOutboundItems(newCtx)
	c.Assert(err, IsNil)
	c.Assert(msgs, HasLen, 1)
	c.Assert(msgs[0].VaultPubKey.String(), Equals, vault.PubKey.String())
	c.Assert(msgs[0].Coin.Amount.Equal(cosmos.NewUint(7999887500)), Equals, true, Commentf("%d", msgs[0].Coin.Amount.Uint64()))

	// make sure outbound_height has been set correctly
	afterVoter, err := w.keeper.GetObservedTxInVoter(w.ctx, inTxID)
	c.Assert(err, IsNil)
	c.Assert(afterVoter.OutboundHeight, Equals, int64(4))

	item.Chain = common.THORChain
	item.Coin = common.NewCoin(common.RuneNative, cosmos.NewUint(100*common.One))
	item.ToAddress = GetRandomTHORAddress()
	ok, err = txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
	c.Assert(err, IsNil)
	c.Assert(ok, Equals, true)

	// make sure outbound_height has not been overwritten
	afterVoter1, err := w.keeper.GetObservedTxInVoter(w.ctx, inTxID)
	c.Assert(err, IsNil)
	c.Assert(afterVoter1.OutboundHeight, Equals, int64(4))
}

func (s TxOutStoreV98Suite) TestAddOutTxItemNotEnoughForFee(c *C) {
	w := getHandlerTestWrapper(c, 1, true, true)
	vault := GetRandomVault()
	vault.Coins = common.Coins{
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(10000*common.One)),
		common.NewCoin(common.BNBAsset, cosmos.NewUint(10000*common.One)),
	}
	c.Assert(w.keeper.SetVault(w.ctx, vault), IsNil)

	acc1 := GetRandomValidatorNode(NodeActive)
	acc2 := GetRandomValidatorNode(NodeActive)
	acc3 := GetRandomValidatorNode(NodeActive)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc1), IsNil)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc2), IsNil)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc3), IsNil)

	ygg := NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc1.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(40*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	ygg = NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc2.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(50*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	ygg = NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc3.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(100*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	// Create voter
	inTxID := GetRandomTxHash()
	voter := NewObservedTxVoter(inTxID, ObservedTxs{
		ObservedTx{
			Tx:             GetRandomTx(),
			Status:         types.Status_incomplete,
			BlockHeight:    1,
			Signers:        []string{w.activeNodeAccount.NodeAddress.String(), acc1.NodeAddress.String(), acc2.NodeAddress.String()},
			KeysignMs:      0,
			FinaliseHeight: 1,
		},
	})
	w.keeper.SetObservedTxInVoter(w.ctx, voter)

	item := TxOutItem{
		Chain:     common.BNBChain,
		ToAddress: GetRandomBNBAddress(),
		InHash:    inTxID,
		Coin:      common.NewCoin(common.BNBAsset, cosmos.NewUint(30000)),
	}
	txOutStore := newTxOutStorageV98(w.keeper, w.mgr.GetConstants(), w.mgr.EventMgr(), w.mgr.GasMgr())
	ok, err := txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
	c.Assert(err, NotNil)
	c.Assert(err, Equals, ErrNotEnoughToPayFee)
	c.Assert(ok, Equals, false)
	msgs, err := txOutStore.GetOutboundItems(w.ctx)
	c.Assert(err, IsNil)
	c.Assert(msgs, HasLen, 0)
}

func (s TxOutStoreV98Suite) TestAddOutTxItemWithoutBFT(c *C) {
	w := getHandlerTestWrapper(c, 1, true, true)
	vault := GetRandomVault()
	vault.Coins = common.Coins{
		common.NewCoin(common.BNBAsset, cosmos.NewUint(100*common.One)),
	}
	c.Assert(w.keeper.SetVault(w.ctx, vault), IsNil)

	inTxID := GetRandomTxHash()
	item := TxOutItem{
		Chain:     common.BNBChain,
		ToAddress: GetRandomBNBAddress(),
		InHash:    inTxID,
		Coin:      common.NewCoin(common.BNBAsset, cosmos.NewUint(20*common.One)),
	}
	txOutStore := newTxOutStorageV98(w.keeper, w.mgr.GetConstants(), w.mgr.EventMgr(), w.mgr.GasMgr())
	success, err := txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
	c.Assert(err, IsNil)
	c.Assert(success, Equals, true)
	msgs, err := txOutStore.GetOutboundItems(w.ctx)
	c.Assert(err, IsNil)
	c.Assert(msgs, HasLen, 1)
	c.Assert(msgs[0].Coin.Amount.Equal(cosmos.NewUint(1999887500)), Equals, true, Commentf("%d", msgs[0].Coin.Amount.Uint64()))
}

func (s TxOutStoreV98Suite) TestAddOutTxItemDeductMaxGasFromYggdrasil(c *C) {
	w := getHandlerTestWrapper(c, 1, true, true)
	vault := GetRandomVault()
	vault.Coins = common.Coins{
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(10000*common.One)),
		common.NewCoin(common.BNBAsset, cosmos.NewUint(10000*common.One)),
	}
	c.Assert(w.keeper.SetVault(w.ctx, vault), IsNil)

	acc1 := GetRandomValidatorNode(NodeActive)
	acc2 := GetRandomValidatorNode(NodeActive)
	acc3 := GetRandomValidatorNode(NodeActive)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc1), IsNil)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc2), IsNil)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc3), IsNil)

	ygg := NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc1.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(11*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	ygg = NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc2.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(50*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	ygg = NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc3.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(100*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	// Create voter
	inTxID := GetRandomTxHash()
	voter := NewObservedTxVoter(inTxID, ObservedTxs{
		ObservedTx{
			Tx:             GetRandomTx(),
			Status:         types.Status_incomplete,
			BlockHeight:    1,
			Signers:        []string{w.activeNodeAccount.NodeAddress.String(), acc1.NodeAddress.String(), acc2.NodeAddress.String()},
			KeysignMs:      0,
			FinaliseHeight: 1,
		},
	})
	w.keeper.SetObservedTxInVoter(w.ctx, voter)

	// Should get acc2. Acc3 hasn't signed and acc2 is the highest value
	item := TxOutItem{
		Chain:     common.BNBChain,
		ToAddress: GetRandomBNBAddress(),
		InHash:    inTxID,
		Coin:      common.NewCoin(common.BNBAsset, cosmos.NewUint(3900000000)),
		MaxGas: common.Gas{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(100000000)),
		},
	}
	txOutStore := newTxOutStorageV98(w.keeper, w.mgr.GetConstants(), w.mgr.EventMgr(), w.mgr.GasMgr())
	ok, err := txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
	c.Assert(err, IsNil)
	c.Assert(ok, Equals, true)
	msgs, err := txOutStore.GetOutboundItems(w.ctx)
	c.Assert(err, IsNil)
	c.Assert(msgs, HasLen, 1)

	item1 := TxOutItem{
		Chain:     common.BNBChain,
		ToAddress: GetRandomBNBAddress(),
		InHash:    inTxID,
		Coin:      common.NewCoin(common.BNBAsset, cosmos.NewUint(1000000000)),
		MaxGas: common.Gas{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(7500)),
		},
	}
	ok, err = txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item1, cosmos.ZeroUint())
	c.Assert(err, IsNil)
	c.Assert(ok, Equals, true)
	msgs, err = txOutStore.GetOutboundItems(w.ctx)
	c.Assert(err, IsNil)
	c.Assert(msgs, HasLen, 2)
	c.Assert(msgs[1].VaultPubKey.Equals(acc1.PubKeySet.Secp256k1), Equals, true)
}

func (s TxOutStoreV98Suite) TestCalcTxOutHeight(c *C) {
	keeper := &TestCalcKeeper{
		value: make(map[int64]cosmos.Uint),
		mimir: make(map[string]int64),
	}

	keeper.mimir["MinTxOutVolumeThreshold"] = 25_00000000
	keeper.mimir["TxOutDelayRate"] = 25_00000000
	keeper.mimir["MaxTxOutOffset"] = 720
	keeper.mimir["TxOutDelayMax"] = 17280

	addValue := func(h int64, v cosmos.Uint) {
		if _, ok := keeper.value[h]; !ok {
			keeper.value[h] = cosmos.ZeroUint()
		}
		keeper.value[h] = keeper.value[h].Add(v)
	}

	ctx, _ := setupManagerForTest(c)

	txout := TxOutStorageV98{keeper: keeper}

	toi := TxOutItem{
		Coin: common.NewCoin(common.BNBAsset, cosmos.NewUint(50*common.One)),
		Memo: "OUT:nomnomnom",
	}
	pool, _ := keeper.GetPool(ctx, common.BNBAsset)
	value := pool.AssetValueInRune(toi.Coin.Amount)

	targetBlock, err := txout.CalcTxOutHeight(ctx, keeper.GetVersion(), toi)
	c.Assert(err, IsNil)
	c.Check(targetBlock, Equals, int64(147))
	addValue(targetBlock, value)

	targetBlock, err = txout.CalcTxOutHeight(ctx, keeper.GetVersion(), toi)
	c.Assert(err, IsNil)
	c.Check(targetBlock, Equals, int64(148))
	addValue(targetBlock, value)

	toi.Coin.Amount = cosmos.NewUint(50000 * common.One)
	targetBlock, err = txout.CalcTxOutHeight(ctx, keeper.GetVersion(), toi)
	c.Assert(err, IsNil)
	c.Check(targetBlock, Equals, int64(738))
	addValue(targetBlock, value)
}

func (s TxOutStoreV98Suite) TestAddOutTxItem_MultipleOutboundWillBeScheduledAtTheSameBlockHeight(c *C) {
	SetupConfigForTest()
	w := getHandlerTestWrapper(c, 1, true, true)
	vault := GetRandomVault()
	vault.Coins = common.Coins{
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(10000*common.One)),
		common.NewCoin(common.BNBAsset, cosmos.NewUint(10000*common.One)),
	}
	c.Assert(w.keeper.SetVault(w.ctx, vault), IsNil)

	acc1 := GetRandomValidatorNode(NodeActive)
	acc2 := GetRandomValidatorNode(NodeActive)
	acc3 := GetRandomValidatorNode(NodeActive)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc1), IsNil)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc2), IsNil)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc3), IsNil)

	ygg := NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc1.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(40*common.One)),
			common.NewCoin(common.BCHAsset, cosmos.NewUint(40*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	ygg = NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc2.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(50*common.One)),
			common.NewCoin(common.BCHAsset, cosmos.NewUint(40*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	ygg = NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc3.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(100*common.One)),
			common.NewCoin(common.BCHAsset, cosmos.NewUint(40*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)
	w.keeper.SetMimir(w.ctx, constants.MinTxOutVolumeThreshold.String(), 100000000000)
	w.keeper.SetMimir(w.ctx, constants.TxOutDelayRate.String(), 2500000000)
	w.keeper.SetMimir(w.ctx, constants.MaxTxOutOffset.String(), 720)
	// Create voter
	inTxID := GetRandomTxHash()
	voter := NewObservedTxVoter(inTxID, ObservedTxs{
		ObservedTx{
			Tx:             GetRandomTx(),
			Status:         types.Status_incomplete,
			BlockHeight:    1,
			Signers:        []string{w.activeNodeAccount.NodeAddress.String(), acc1.NodeAddress.String(), acc2.NodeAddress.String()},
			KeysignMs:      0,
			FinaliseHeight: 1,
		},
	})
	w.keeper.SetObservedTxInVoter(w.ctx, voter)

	// this should be sent via asgard
	item := TxOutItem{
		Chain:     common.BNBChain,
		ToAddress: GetRandomBNBAddress(),
		InHash:    inTxID,
		Coin:      common.NewCoin(common.BNBAsset, cosmos.NewUint(80*common.One)),
	}
	txOutStore := newTxOutStorageV98(w.keeper, w.mgr.GetConstants(), w.mgr.EventMgr(), w.mgr.GasMgr())
	ok, err := txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
	c.Assert(err, IsNil)
	c.Assert(ok, Equals, true)

	item1 := TxOutItem{
		Chain:     common.BNBChain,
		ToAddress: GetRandomBNBAddress(),
		InHash:    inTxID,
		Coin:      common.NewCoin(common.BNBAsset, cosmos.NewUint(common.One)),
	}

	ok, err = txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item1, cosmos.ZeroUint())
	c.Assert(err, IsNil)
	c.Assert(ok, Equals, true)

	msgs, err := txOutStore.GetOutboundItems(w.ctx)
	c.Assert(err, IsNil)
	c.Assert(msgs, HasLen, 0)
	//  the outbound has been delayed
	newCtx := w.ctx.WithBlockHeight(4)
	msgs, err = txOutStore.GetOutboundItems(newCtx)
	c.Assert(err, IsNil)
	c.Assert(msgs, HasLen, 2)
	c.Assert(msgs[0].VaultPubKey.String(), Equals, vault.PubKey.String())
	c.Assert(msgs[0].Coin.Amount.Equal(cosmos.NewUint(7999887500)), Equals, true, Commentf("%d", msgs[0].Coin.Amount.Uint64()))

	// make sure outbound_height has been set correctly
	afterVoter, err := w.keeper.GetObservedTxInVoter(w.ctx, inTxID)
	c.Assert(err, IsNil)
	c.Assert(afterVoter.OutboundHeight, Equals, int64(4))

	item.Chain = common.THORChain
	item.Coin = common.NewCoin(common.RuneNative, cosmos.NewUint(100*common.One))
	item.ToAddress = GetRandomTHORAddress()
	ok, err = txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
	c.Assert(err, IsNil)
	c.Assert(ok, Equals, true)

	// make sure outbound_height has not been overwritten
	afterVoter1, err := w.keeper.GetObservedTxInVoter(w.ctx, inTxID)
	c.Assert(err, IsNil)
	c.Assert(afterVoter1.OutboundHeight, Equals, int64(4))
}

func (s TxOutStoreV98Suite) TestAddOutTxItemInteractionWithPool(c *C) {
	w := getHandlerTestWrapper(c, 1, true, true)
	pool, err := w.keeper.GetPool(w.ctx, common.BNBAsset)
	c.Assert(err, IsNil)
	// Set unequal values for the pool balances for this test.
	pool.BalanceAsset = cosmos.NewUint(50 * common.One)
	pool.BalanceRune = cosmos.NewUint(100 * common.One)
	err = w.keeper.SetPool(w.ctx, pool)
	c.Assert(err, IsNil)

	vault := GetRandomVault()
	vault.Coins = common.Coins{
		common.NewCoin(common.BNBAsset, cosmos.NewUint(100*common.One)),
	}
	c.Assert(w.keeper.SetVault(w.ctx, vault), IsNil)

	inTxID := GetRandomTxHash()
	item := TxOutItem{
		Chain:     common.BNBChain,
		ToAddress: GetRandomBNBAddress(),
		InHash:    inTxID,
		Coin:      common.NewCoin(common.BNBAsset, cosmos.NewUint(20*common.One)),
	}
	txOutStore := newTxOutStorageV98(w.keeper, w.mgr.GetConstants(), w.mgr.EventMgr(), w.mgr.GasMgr())
	success, err := txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
	c.Assert(err, IsNil)
	c.Assert(success, Equals, true)
	msgs, err := txOutStore.GetOutboundItems(w.ctx)
	c.Assert(err, IsNil)
	c.Assert(msgs, HasLen, 1)
	c.Assert(msgs[0].Coin.Amount.Equal(cosmos.NewUint(1999887500)), Equals, true, Commentf("%d", msgs[0].Coin.Amount.Uint64()))
	pool, err = w.keeper.GetPool(w.ctx, common.BNBAsset)
	c.Assert(err, IsNil)
	// Let:
	//   R_0 := the initial pool Rune balance
	//   A_0 := the initial pool Asset balance
	//   a   := the gas amount in Asset
	// Then the expected pool balances are:
	//   A_1 = A_0 + a = 50e8 + (20e8 - 1999887500) = 5000112500
	//   R_1 = R_0 - R_0 * a / (A_0 + a)  // slip formula
	//       = 100e8 - 100e8 * (20e8 - 1999887500) / (50e8 + (20e8 - 1999887500)) = 9999775005
	c.Assert(pool.BalanceAsset.Equal(cosmos.NewUint(5000112500)), Equals, true, Commentf("%d", pool.BalanceAsset.Uint64()))
	c.Assert(pool.BalanceRune.Equal(cosmos.NewUint(9999775005)), Equals, true, Commentf("%d", pool.BalanceRune.Uint64()))
}

func (s TxOutStoreV98Suite) TestAddOutTxItemSendingFromRetiredVault(c *C) {
	SetupConfigForTest()
	w := getHandlerTestWrapper(c, 1, true, true)
	activeVault1 := GetRandomVault()
	activeVault1.Type = AsgardVault
	activeVault1.Status = ActiveVault
	activeVault1.Coins = common.Coins{
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(10000*common.One)),
		common.NewCoin(common.BNBAsset, cosmos.NewUint(100*common.One)),
	}
	c.Assert(w.keeper.SetVault(w.ctx, activeVault1), IsNil)

	activeVault2 := GetRandomVault()
	activeVault2.Type = AsgardVault
	activeVault2.Status = ActiveVault
	activeVault2.Coins = common.Coins{
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(10000*common.One)),
		common.NewCoin(common.BNBAsset, cosmos.NewUint(100*common.One)),
	}
	c.Assert(w.keeper.SetVault(w.ctx, activeVault2), IsNil)

	retiringVault1 := GetRandomVault()
	retiringVault1.Type = AsgardVault
	retiringVault1.Status = RetiringVault
	retiringVault1.Coins = common.Coins{
		common.NewCoin(common.RuneAsset(), cosmos.NewUint(10000*common.One)),
		common.NewCoin(common.BNBAsset, cosmos.NewUint(1000*common.One)),
	}
	c.Assert(w.keeper.SetVault(w.ctx, retiringVault1), IsNil)
	acc1 := GetRandomValidatorNode(NodeActive)
	acc2 := GetRandomValidatorNode(NodeActive)
	acc3 := GetRandomValidatorNode(NodeActive)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc1), IsNil)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc2), IsNil)
	c.Assert(w.keeper.SetNodeAccount(w.ctx, acc3), IsNil)

	ygg := NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc1.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	ygg.AddFunds(
		common.Coins{
			common.NewCoin(common.BNBAsset, cosmos.NewUint(10*common.One)),
		},
	)
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	ygg = NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc2.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	ygg = NewVault(w.ctx.BlockHeight(), ActiveVault, YggdrasilVault, acc3.PubKeySet.Secp256k1, common.Chains{common.BNBChain}.Strings(), []ChainContract{})
	c.Assert(w.keeper.SetVault(w.ctx, ygg), IsNil)

	w.keeper.SetMimir(w.ctx, constants.MinTxOutVolumeThreshold.String(), 10000000000000)
	w.keeper.SetMimir(w.ctx, constants.TxOutDelayRate.String(), 250000000000)
	w.keeper.SetMimir(w.ctx, constants.MaxTxOutOffset.String(), 720)
	// Create voter
	inTxID := GetRandomTxHash()
	voter := NewObservedTxVoter(inTxID, ObservedTxs{
		ObservedTx{
			Tx:             GetRandomTx(),
			Status:         types.Status_incomplete,
			BlockHeight:    1,
			Signers:        []string{w.activeNodeAccount.NodeAddress.String(), acc1.NodeAddress.String(), acc2.NodeAddress.String()},
			KeysignMs:      0,
			FinaliseHeight: 1,
		},
	})
	w.keeper.SetObservedTxInVoter(w.ctx, voter)

	// this should be sent via asgard
	item := TxOutItem{
		Chain:     common.BNBChain,
		ToAddress: GetRandomBNBAddress(),
		InHash:    inTxID,
		Coin:      common.NewCoin(common.BNBAsset, cosmos.NewUint(120*common.One)),
	}
	txOutStore := newTxOutStorageV98(w.keeper, w.mgr.GetConstants(), w.mgr.EventMgr(), w.mgr.GasMgr())
	ok, err := txOutStore.TryAddTxOutItem(w.ctx, w.mgr, item, cosmos.ZeroUint())
	c.Assert(err, IsNil)
	c.Assert(ok, Equals, true)

	msgs, err := txOutStore.GetOutboundItems(w.ctx)
	c.Assert(err, IsNil)
	c.Assert(msgs, HasLen, 1)
}
