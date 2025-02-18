package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog/log"
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/x/thorchain"
)

////////////////////////////////////////////////////////////////////////////////////////
// Export
////////////////////////////////////////////////////////////////////////////////////////

func export(path string) error {
	// export state
	log.Debug().Msg("Exporting state")
	cmd := exec.Command("thornode", "export")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to export state")
	}

	// decode export
	var export map[string]any
	err = json.Unmarshal(out, &export)
	if err != nil {
		fmt.Println(string(out))
		log.Fatal().Err(err).Msg("failed to decode export")
	}

	// ignore genesis time and version for comparison
	delete(export, "genesis_time")
	appState, _ := export["app_state"].(map[string]any)
	thorchain, _ := appState["thorchain"].(map[string]any)
	delete(thorchain, "store_version")

	// ignore node account version for comparison
	nodeAccounts, _ := thorchain["node_accounts"].([]interface{})
	for i, na := range nodeAccounts {
		na, _ := na.(map[string]interface{})
		delete(na, "version")
		nodeAccounts[i] = na
	}

	// encode export
	out, err = json.MarshalIndent(export, "", "  ")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to encode export")
	}

	// base path without extension and replace path separators with underscores
	exportName := strings.TrimSuffix(path, filepath.Ext(path))
	exportName = strings.ReplaceAll(exportName, string(os.PathSeparator), "_")
	exportPath := fmt.Sprintf("/mnt/exports/%s.json", exportName)

	// check whether existing export exists
	_, err = os.Stat(exportPath)
	exportExists := err == nil

	// check export invariants
	err = checkExportInvariants(export)
	if err != nil {
		// also log export changes for easier debugging
		if exportExists {
			_ = checkExportChanges(export, exportPath)
		}

		return err
	}

	// export if it none exists or EXPORT is set
	if !exportExists || os.Getenv("EXPORT") != "" {
		log.Debug().Msg("Writing export")
		err = os.WriteFile(exportPath, out, 0o600)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to write export")
		}
		return nil
	}

	return checkExportChanges(export, exportPath)
}

////////////////////////////////////////////////////////////////////////////////////////
// Checks
////////////////////////////////////////////////////////////////////////////////////////

func checkExportInvariants(genesis map[string]any) error {
	// check export invariants
	log.Debug().Msg("Checking export invariants")
	appState, _ := genesis["app_state"].(map[string]any)

	// encode thorchain state to json for custom unmarshal
	buf := bytes.NewBuffer(nil)
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")
	err := enc.Encode(appState["thorchain"])
	if err != nil {
		log.Fatal().Err(err).Msg("failed to encode genesis state")
	}

	// unmarshal json to genesis state
	genesisState := &thorchain.GenesisState{}
	err = encodingConfig.Marshaler.UnmarshalJSON(buf.Bytes(), genesisState)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to decode genesis state")
	}

	// sum of pool + outbounds should be less than or equal to sum of vaults
	var sumPoolAsset, sumVaultAsset common.Coins
	poolAssets := map[common.Asset]bool{}
	for _, pool := range genesisState.Pools {
		poolAssets[pool.Asset] = true
		sumPoolAsset = sumPoolAsset.Add(common.NewCoin(pool.Asset, pool.BalanceAsset))
	}
	for _, vault := range genesisState.Vaults {
		// only count coins with pools
		for _, coin := range vault.Coins {
			if poolAssets[coin.Asset] {
				sumVaultAsset = sumVaultAsset.Add(coin)
			}
		}
	}
	for _, txout := range genesisState.TxOuts {
		for _, toi := range txout.TxArray {
			sumPoolAsset = sumPoolAsset.Add(toi.Coin)
		}
	}

	// print any discrepencies
	for _, coin := range sumPoolAsset {
		for _, vaultCoin := range sumVaultAsset {
			if coin.Asset.Equals(vaultCoin.Asset) && !coin.Amount.Equal(vaultCoin.Amount) {
				if coin.Amount.GT(vaultCoin.Amount) {
					fmt.Printf("%s pool has %s more than its vaults\n", coin.Asset, common.SafeSub(vaultCoin.Amount, coin.Amount))
				}
				if vaultCoin.Amount.GT(coin.Amount) {
					fmt.Printf("%s vaults have %s more than their pool\n", coin.Asset, common.SafeSub(vaultCoin.Amount, coin.Amount))
				}
				err = errors.New("pool discrepancy")
			}
		}
	}

	// print outbounds for debugging
	if err != nil {
		for _, txout := range genesisState.TxOuts {
			for _, toi := range txout.TxArray {
				fmt.Printf("%s outbound: %s\n", toi.Coin.Asset, toi.Coin.Amount)
			}
		}
	}

	return err
}

func checkExportChanges(newExport map[string]any, path string) error {
	// compare existing export
	log.Debug().Msg("Reading existing export")

	// open existing export
	f, err := os.Open(path)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open existing export")
	}
	defer f.Close()

	// decode existing export
	oldExport := map[string]any{}
	err = json.NewDecoder(f).Decode(&oldExport)
	if err != nil {
		log.Err(err).Msg("failed to decode existing export")
	}

	// compare exports
	log.Debug().Msg("Comparing exports")
	diff := cmp.Diff(oldExport, newExport)
	if diff != "" {
		log.Error().Msgf("exports differ: %s", diff)
		return errors.New("exports differ")
	}

	log.Info().Msg("State export matches expected")
	return nil
}
