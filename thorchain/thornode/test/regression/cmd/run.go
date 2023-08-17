package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"text/template"
	"time"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

////////////////////////////////////////////////////////////////////////////////////////
// Run
////////////////////////////////////////////////////////////////////////////////////////

func run(path string) error {
	log.Info().Msgf("Running regression test: %s", path)

	// reset native txids
	nativeTxIDs = nativeTxIDs[:0]

	// clear data directory
	log.Debug().Msg("Clearing data directory")
	out, err := exec.Command("rm", "-rf", "/regtest/.thornode").CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
		log.Fatal().Err(err).Msg("failed to clear data directory")
	}

	// init chain with dog mnemonic
	log.Debug().Msg("Initializing chain")
	cmd := exec.Command("thornode", "init", "local", "--chain-id", "thorchain", "--recover")
	cmd.Stdin = bytes.NewBufferString(dogMnemonic + "\n")
	out, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
		log.Fatal().Err(err).Msg("failed to initialize chain")
	}

	// init chain
	log.Debug().Msg("Initializing chain")
	cmd = exec.Command("thornode", "init", "local", "--chain-id", "thorchain", "-o")
	out, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
		log.Fatal().Err(err).Msg("failed to initialize chain")
	}

	// clone common templates
	tmpls := template.Must(templates.Clone())

	// ensure no naming collisions
	if tmpls.Lookup(filepath.Base(path)) != nil {
		log.Fatal().Msgf("test name collision: %s", filepath.Base(path))
	}

	// read the file
	f, err := os.Open(path)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open test file")
	}
	fileBytes, err := io.ReadAll(f)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to read test file")
	}
	f.Close()

	// track line numbers
	opLines := []int{0}
	scanner := bufio.NewScanner(bytes.NewBuffer(fileBytes))
	for i := 0; scanner.Scan(); i++ {
		line := scanner.Text()
		if line == "---" {
			opLines = append(opLines, i+2)
		}
	}

	// parse the template
	tmpl, err := tmpls.Parse(string(fileBytes))
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse template")
	}

	// render the template
	buf := &bytes.Buffer{}
	err = tmpl.Execute(buf, nil)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to render template")
	}

	// all operations we will execute
	ops := []Operation{}

	// track whether we've seen non-state operations
	seenNonState := false

	dec := yaml.NewDecoder(buf)
	for {
		// decode into temporary type
		op := map[string]any{}
		err = dec.Decode(&op)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal().Err(err).Msg("failed to decode operation")
		}

		// warn empty operations
		if len(op) == 0 {
			log.Warn().Msg("empty operation, line numbers may be wrong")
			continue
		}

		// state operations must be first
		if op["type"] == "state" && seenNonState {
			log.Fatal().Msg("state operations must be first")
		}
		if op["type"] != "state" {
			seenNonState = true
		}

		ops = append(ops, NewOperation(op))
	}

	// warn if no operations found
	if len(ops) == 0 {
		err = errors.New("no operations found")
		log.Err(err).Msg("")
		return err
	}

	// execute all state operations
	stateOpCount := 0
	for i, op := range ops {
		if _, ok := op.(*OpState); ok {
			log.Info().Int("line", opLines[i]).Msgf(">>> [%d] %s", i+1, op.OpType())
			err = op.Execute(nil, nil)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to execute state operation")
			}
			stateOpCount++
		}
	}
	ops = ops[stateOpCount:]
	opLines = opLines[stateOpCount:]

	// validate genesis
	log.Debug().Msg("Validating genesis")
	cmd = exec.Command("thornode", "validate-genesis")
	out, err = cmd.CombinedOutput()
	if err != nil {
		// dump the genesis
		fmt.Println(ColorPurple + "Genesis:" + ColorReset)
		f, err := os.OpenFile("/regtest/.thornode/config/genesis.json", os.O_RDWR, 0o644)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to open genesis file")
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
		f.Close()

		// dump error and exit
		fmt.Println(string(out))
		log.Fatal().Err(err).Msg("genesis validation failed")
	}

	// render config
	log.Debug().Msg("Rendering config")
	cmd = exec.Command("thornode", "render-config")
	// block time should be short, but all consecutive checks must complete within timeout
	cmd.Env = append(os.Environ(), fmt.Sprintf("THOR_TENDERMINT_CONSENSUS_TIMEOUT_COMMIT=%s", time.Second*getTimeFactor()))
	err = cmd.Run()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to render config")
	}

	// overwrite private validator key
	log.Debug().Msg("Overwriting private validator key")
	cmd = exec.Command("cp", "/mnt/priv_validator_key.json", "/regtest/.thornode/config/priv_validator_key.json")
	err = cmd.Run()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to overwrite private validator key")
	}

	// setup process io
	thornode := exec.Command("/regtest/cover-thornode", "start")
	thornode.Env = append(os.Environ(), "GOCOVERDIR=/mnt/coverage")
	stderr, err := thornode.StderrPipe()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to setup thornode stderr")
	}
	stderrScanner := bufio.NewScanner(stderr)
	stderrLines := make(chan string, 100)
	go func() {
		for stderrScanner.Scan() {
			stderrLines <- stderrScanner.Text()
		}
	}()
	if os.Getenv("DEBUG") != "" {
		thornode.Stdout = os.Stdout
		thornode.Stderr = os.Stderr
	}

	// start thornode process
	log.Debug().Msg("Starting thornode")
	err = thornode.Start()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to start thornode")
	}

	// wait for thornode to listen on block creation port
	for i := 0; ; i++ {
		time.Sleep(100 * time.Millisecond)
		conn, err := net.Dial("tcp", "localhost:8080")
		if err == nil {
			conn.Close()
			break
		}
		if i%100 == 0 {
			log.Debug().Msg("Waiting for thornode to listen")
		}
	}

	// run the operations
	var returnErr error
	log.Info().Msgf("Executing %d operations", len(ops))
	for i, op := range ops {
		log.Info().Int("line", opLines[i]).Msgf(">>> [%d] %s", stateOpCount+i+1, op.OpType())
		returnErr = op.Execute(thornode.Process, stderrLines)
		if returnErr != nil {
			log.Error().Err(returnErr).
				Int("line", opLines[i]).
				Int("op", stateOpCount+i+1).
				Str("type", op.OpType()).
				Str("path", path).
				Msg("operation failed")
			fmt.Println()
			dumpLogs(stderrLines)
			break
		}
	}

	// log success
	if returnErr == nil {
		log.Info().Msg("All operations succeeded")
	}

	// stop thornode process
	log.Debug().Msg("Stopping thornode")
	err = thornode.Process.Signal(syscall.SIGUSR1)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to stop thornode")
	}

	// wait for process to exit
	_, err = thornode.Process.Wait()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to wait for thornode")
	}

	// if failed and debug enabled restart to allow inspection
	if returnErr != nil && os.Getenv("DEBUG") != "" {

		// remove validator key (otherwise thornode will hang in begin block)
		log.Debug().Msg("Removing validator key")
		cmd = exec.Command("rm", "/regtest/.thornode/config/priv_validator_key.json")
		out, err = cmd.CombinedOutput()
		if err != nil {
			fmt.Println(string(out))
			log.Fatal().Err(err).Msg("failed to remove validator key")
		}

		// restart thornode
		log.Debug().Msg("Restarting thornode")
		thornode = exec.Command("thornode", "start", "--filter-modules=\"\"")
		thornode.Stdout = os.Stdout
		thornode.Stderr = os.Stderr
		err = thornode.Start()
		if err != nil {
			log.Fatal().Err(err).Msg("failed to restart thornode")
		}

		// wait for thornode
		log.Debug().Msg("Waiting for thornode")
		_, err = thornode.Process.Wait()
		if err != nil {
			log.Fatal().Err(err).Msg("failed to wait for thornode")
		}
	}

	return returnErr
}
