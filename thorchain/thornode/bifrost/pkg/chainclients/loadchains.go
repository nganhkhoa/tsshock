package chainclients

import (
	"github.com/rs/zerolog/log"
	"gitlab.com/thorchain/tss/go-tss/tss"

	"gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/dogecoin"
	"gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/gaia"

	"gitlab.com/thorchain/thornode/bifrost/metrics"
	"gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/avalanche"
	"gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/binance"
	"gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/bitcoin"
	"gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/bitcoincash"
	"gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/ethereum"
	"gitlab.com/thorchain/thornode/bifrost/pkg/chainclients/litecoin"
	"gitlab.com/thorchain/thornode/bifrost/pubkeymanager"
	"gitlab.com/thorchain/thornode/bifrost/thorclient"
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/config"
)

// LoadChains returns chain clients from chain configuration
func LoadChains(thorKeys *thorclient.Keys,
	cfg map[common.Chain]config.BifrostChainConfiguration,
	server *tss.TssServer,
	thorchainBridge *thorclient.ThorchainBridge,
	m *metrics.Metrics,
	pubKeyValidator pubkeymanager.PubKeyValidator,
	poolMgr thorclient.PoolManager,
) map[common.Chain]ChainClient {
	logger := log.Logger.With().Str("module", "bifrost").Logger()
	chains := make(map[common.Chain]ChainClient)

	for _, chain := range cfg {
		if chain.Disabled {
			logger.Info().Msgf("%s chain is disabled by configure", chain.ChainID)
			continue
		}
		switch chain.ChainID {
		case common.BNBChain:
			bnb, err := binance.NewBinance(thorKeys, chain, server, thorchainBridge, m)
			if err != nil {
				logger.Fatal().Err(err).Str("chain_id", chain.ChainID.String()).Msg("fail to load chain")
				continue
			}
			chains[common.BNBChain] = bnb
		case common.ETHChain:
			eth, err := ethereum.NewClient(thorKeys, chain, server, thorchainBridge, m, pubKeyValidator, poolMgr)
			if err != nil {
				logger.Fatal().Err(err).Str("chain_id", chain.ChainID.String()).Msg("fail to load chain")
				continue
			}
			chains[common.ETHChain] = eth
		case common.BTCChain:
			btc, err := bitcoin.NewClient(thorKeys, chain, server, thorchainBridge, m)
			if err != nil {
				logger.Fatal().Err(err).Str("chain_id", chain.ChainID.String()).Msg("fail to load chain")
				continue
			}
			pubKeyValidator.RegisterCallback(btc.RegisterPublicKey)
			chains[common.BTCChain] = btc
		case common.BCHChain:
			bch, err := bitcoincash.NewClient(thorKeys, chain, server, thorchainBridge, m)
			if err != nil {
				logger.Fatal().Err(err).Str("chain_id", chain.ChainID.String()).Msg("fail to load chain")
				continue
			}
			pubKeyValidator.RegisterCallback(bch.RegisterPublicKey)
			chains[common.BCHChain] = bch
		case common.LTCChain:
			ltc, err := litecoin.NewClient(thorKeys, chain, server, thorchainBridge, m)
			if err != nil {
				logger.Fatal().Err(err).Str("chain_id", chain.ChainID.String()).Msg("fail to load chain")
				continue
			}
			pubKeyValidator.RegisterCallback(ltc.RegisterPublicKey)
			chains[common.LTCChain] = ltc
		case common.DOGEChain:
			doge, err := dogecoin.NewClient(thorKeys, chain, server, thorchainBridge, m)
			if err != nil {
				logger.Fatal().Err(err).Str("chain_id", chain.ChainID.String()).Msg("fail to load chain")
				continue
			}
			pubKeyValidator.RegisterCallback(doge.RegisterPublicKey)
			chains[common.DOGEChain] = doge
		case common.AVAXChain:
			avax, err := avalanche.NewAvalancheClient(thorKeys, chain, server, thorchainBridge, m, pubKeyValidator, poolMgr)
			if err != nil {
				logger.Fatal().Err(err).Str("chain_id", chain.ChainID.String()).Msg("fail to load chain")
				continue
			}
			chains[common.AVAXChain] = avax
		case common.GAIAChain:
			gaia, err := gaia.NewCosmosClient(thorKeys, chain, server, thorchainBridge, m)
			if err != nil {
				logger.Fatal().Err(err).Str("chain_id", chain.ChainID.String()).Msg("fail to load chain")
				continue
			}
			chains[common.GAIAChain] = gaia
		}
	}

	return chains
}
