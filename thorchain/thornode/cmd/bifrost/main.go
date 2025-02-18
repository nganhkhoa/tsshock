package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	btsskeygen "github.com/binance-chain/tss-lib/ecdsa/keygen"
	golog "github.com/ipfs/go-log"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	flag "github.com/spf13/pflag"

	"gitlab.com/thorchain/tss/go-tss/common"
	"gitlab.com/thorchain/tss/go-tss/tss"

	"gitlab.com/thorchain/thornode/app"
	"gitlab.com/thorchain/thornode/bifrost/metrics"
	"gitlab.com/thorchain/thornode/bifrost/observer"
	"gitlab.com/thorchain/thornode/bifrost/pkg/chainclients"
	"gitlab.com/thorchain/thornode/bifrost/pubkeymanager"
	"gitlab.com/thorchain/thornode/bifrost/signer"
	"gitlab.com/thorchain/thornode/bifrost/thorclient"
	btss "gitlab.com/thorchain/thornode/bifrost/tss"
	"gitlab.com/thorchain/thornode/cmd"
	tcommon "gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	"gitlab.com/thorchain/thornode/config"
)

// THORNode define version / revision here , so THORNode could inject the version from CI pipeline if THORNode want to
var (
	version  string
	revision string
)

const (
	serverIdentity = "bifrost"
)

func printVersion() {
	fmt.Printf("%s v%s, rev %s\n", serverIdentity, version, revision)
}

func main() {
	showVersion := flag.Bool("version", false, "Shows version")
	logLevel := flag.StringP("log-level", "l", "info", "Log Level")
	pretty := flag.BoolP("pretty-log", "p", false, "Enables unstructured prettified logging. This is useful for local debugging")
	tssPreParam := flag.StringP("preparm", "t", "", "pre-generated PreParam file used for tss")
	flag.Parse()

	if *showVersion {
		printVersion()
		return
	}

	initPrefix()
	initLog(*logLevel, *pretty)
	config.Init()
	config.InitBifrost()
	cfg := config.GetBifrost()

	// metrics
	m, err := metrics.NewMetrics(cfg.Metrics)
	if err != nil {
		log.Fatal().Err(err).Msg("fail to create metric instance")
	}
	if err := m.Start(); err != nil {
		log.Fatal().Err(err).Msg("fail to start metric collector")
	}
	if len(cfg.Thorchain.SignerName) == 0 {
		log.Fatal().Msg("signer name is empty")
	}
	if len(cfg.Thorchain.SignerPasswd) == 0 {
		log.Fatal().Msg("signer password is empty")
	}
	kb, _, err := thorclient.GetKeyringKeybase(cfg.Thorchain.ChainHomeFolder, cfg.Thorchain.SignerName, cfg.Thorchain.SignerPasswd)
	if err != nil {
		log.Fatal().Err(err).Msg("fail to get keyring keybase")
	}

	k := thorclient.NewKeysWithKeybase(kb, cfg.Thorchain.SignerName, cfg.Thorchain.SignerPasswd)
	// thorchain bridge
	thorchainBridge, err := thorclient.NewThorchainBridge(cfg.Thorchain, m, k)
	if err != nil {
		log.Fatal().Err(err).Msg("fail to create new thorchain bridge")
	}
	if err := thorchainBridge.EnsureNodeWhitelistedWithTimeout(); err != nil {
		log.Fatal().Err(err).Msg("node account is not whitelisted, can't start")
	}
	// PubKey Manager
	pubkeyMgr, err := pubkeymanager.NewPubKeyManager(thorchainBridge, m)
	if err != nil {
		log.Fatal().Err(err).Msg("fail to create pubkey manager")
	}
	if err := pubkeyMgr.Start(); err != nil {
		log.Fatal().Err(err).Msg("fail to start pubkey manager")
	}

	// automatically attempt to recover TSS keyshares if they are missing
	if err = btss.RecoverKeyShares(cfg, thorchainBridge); err != nil {
		log.Error().Err(err).Msg("fail to recover key shares")
	}

	// setup TSS signing
	priKey, err := k.GetPrivateKey()
	if err != nil {
		log.Fatal().Err(err).Msg("fail to get private key")
	}

	bootstrapPeers, err := cfg.TSS.GetBootstrapPeers()
	if err != nil {
		log.Fatal().Err(err).Msg("fail to get bootstrap peers")
	}
	tmPrivateKey := tcommon.CosmosPrivateKeyToTMPrivateKey(priKey)
	tssIns, err := tss.NewTss(
		bootstrapPeers,
		cfg.TSS.P2PPort,
		tmPrivateKey,
		cfg.TSS.Rendezvous,
		app.DefaultNodeHome(),
		common.TssConfig{
			EnableMonitor:   true,
			KeyGenTimeout:   300 * time.Second, // must be shorter than constants.JailTimeKeygen
			KeySignTimeout:  60 * time.Second,  // must be shorter than constants.JailTimeKeysign
			PartyTimeout:    45 * time.Second,
			PreParamTimeout: 5 * time.Minute,
		},
		getLocalPreParam(*tssPreParam),
		cfg.TSS.ExternalIP,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("fail to create tss instance")
	}

	if err := tssIns.Start(); err != nil {
		log.Err(err).Msg("fail to start tss instance")
	}

	healthServer := NewHealthServer(cfg.TSS.InfoAddress, tssIns)
	go func() {
		defer log.Info().Msg("health server exit")
		if err := healthServer.Start(); err != nil {
			log.Error().Err(err).Msg("fail to start health server")
		}
	}()
	if len(cfg.Chains) == 0 {
		log.Fatal().Err(err).Msg("missing chains")
		return
	}

	// ensure we have a protocol for chain RPC Hosts
	for _, chainCfg := range cfg.Chains {
		if chainCfg.Disabled {
			continue
		}
		if len(chainCfg.RPCHost) == 0 {
			log.Fatal().Err(err).Stringer("chain", chainCfg.ChainID).Msg("missing chain RPC host")
			return
		}
		if !strings.HasPrefix(chainCfg.RPCHost, "http") {
			chainCfg.RPCHost = fmt.Sprintf("http://%s", chainCfg.RPCHost)
		}

		if len(chainCfg.BlockScanner.RPCHost) == 0 {
			log.Fatal().Err(err).Msg("missing chain RPC host")
			return
		}
		if !strings.HasPrefix(chainCfg.BlockScanner.RPCHost, "http") {
			chainCfg.BlockScanner.RPCHost = fmt.Sprintf("http://%s", chainCfg.BlockScanner.RPCHost)
		}
	}
	poolMgr := thorclient.NewPoolMgr(thorchainBridge)
	chains := chainclients.LoadChains(k, cfg.Chains, tssIns, thorchainBridge, m, pubkeyMgr, poolMgr)
	if len(chains) == 0 {
		log.Fatal().Msg("fail to load any chains")
	}
	tssKeysignMetricMgr := metrics.NewTssKeysignMetricMgr()
	// start signer
	sign, err := signer.NewSigner(cfg.Signer, thorchainBridge, k, pubkeyMgr, tssIns, chains, m, tssKeysignMetricMgr)
	if err != nil {
		log.Fatal().Err(err).Msg("fail to create instance of signer")
	}
	if err := sign.Start(); err != nil {
		log.Fatal().Err(err).Msg("fail to start signer")
	}

	// start observer
	obs, err := observer.NewObserver(pubkeyMgr, chains, thorchainBridge, m, cfg.Chains[tcommon.BTCChain].BlockScanner.DBPath, tssKeysignMetricMgr)
	if err != nil {
		log.Fatal().Err(err).Msg("fail to create observer")
	}
	if err = obs.Start(); err != nil {
		log.Fatal().Err(err).Msg("fail to start observer")
	}

	// wait....
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	log.Info().Msg("stop signal received")

	// stop observer
	if err := obs.Stop(); err != nil {
		log.Fatal().Err(err).Msg("fail to stop observer")
	}
	// stop signer
	if err := sign.Stop(); err != nil {
		log.Fatal().Err(err).Msg("fail to stop signer")
	}
	// stop go tss
	tssIns.Stop()
	if err := healthServer.Stop(); err != nil {
		log.Fatal().Err(err).Msg("fail to stop health server")
	}
}

func initPrefix() {
	cosmosSDKConfg := cosmos.GetConfig()
	cosmosSDKConfg.SetBech32PrefixForAccount(cmd.Bech32PrefixAccAddr, cmd.Bech32PrefixAccPub)
	cosmosSDKConfg.Seal()
}

func initLog(level string, pretty bool) {
	l, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Warn().Msgf("%s is not a valid log-level, falling back to 'info'", level)
	}
	var out io.Writer = os.Stdout
	if pretty {
		out = zerolog.ConsoleWriter{Out: os.Stdout}
	}
	zerolog.SetGlobalLevel(l)
	log.Logger = log.Output(out).With().Caller().Str("service", serverIdentity).Logger()

	logLevel := golog.LevelInfo
	switch l {
	case zerolog.DebugLevel:
		logLevel = golog.LevelDebug
	case zerolog.InfoLevel:
		logLevel = golog.LevelInfo
	case zerolog.ErrorLevel:
		logLevel = golog.LevelError
	case zerolog.FatalLevel:
		logLevel = golog.LevelFatal
	case zerolog.PanicLevel:
		logLevel = golog.LevelPanic
	}
	golog.SetAllLoggers(logLevel)
	if err := golog.SetLogLevel("tss-lib", level); err != nil {
		log.Fatal().Err(err).Msg("fail to set tss-lib loglevel")
	}
}

func getLocalPreParam(file string) *btsskeygen.LocalPreParams {
	if len(file) == 0 {
		return nil
	}
	// #nosec G304 this is to read a file provided by a start up parameter , it will not be any random user input
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal().Msgf("fail to read file:%s", file)
		return nil
	}
	buf = bytes.Trim(buf, "\n")
	log.Info().Msg(string(buf))
	result, err := hex.DecodeString(string(buf))
	if err != nil {
		log.Fatal().Msg("fail to hex decode the file content")
		return nil
	}
	var preParam btsskeygen.LocalPreParams
	if err := json.Unmarshal(result, &preParam); err != nil {
		log.Fatal().Msg("fail to unmarshal file content to LocalPreParams")
		return nil
	}
	return &preParam
}
