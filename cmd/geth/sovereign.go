package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/dop251/goja"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/console"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/internal/jsre"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/urfave/cli/v2"
)

var (

	sovereignCommand = &cli.Command{
		Action: sovereign,
		Name:   "sovereign",
		Usage:  "Start an interactive JavaScript environment",
		Flags:  flags.Merge(nodeFlags, rpcFlags, consoleFlags),
		Description: `
The Geth sovereign is an interactive shell for the JavaScript runtime environment
which exposes a node admin interface as well as the Ðapp JavaScript API.
See https://geth.ethereum.org/docs/interface/javascript-console.`,
	}
)

const (
	accountsCount = 10
)

type Account ecdsa.PrivateKey

func makeAccounts() (accounts []*Account) {
	for i := 0; i < accountsCount; i++ {
		key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		accounts = append(accounts, (*Account)(key))
	}
	return
}

type environment struct {
	signer types.Signer
	gp *core.GasPool
	parent *types.Block
	header *types.Header
	cache state.Database
	state *state.StateDB
	coinbase common.Address
	chainConfig *params.ChainConfig
	tcount int
}

func (env *environment) GetCode(call jsre.Call) (goja.Value, error) {
	addr := common.HexToAddress(call.Arguments[0].String())
	data := env.state.GetCode(addr)
	return call.VM.ToValue(hex.EncodeToString(data)), nil
}

func (env *environment) GetCodeHash(call jsre.Call) (goja.Value, error) {
	addr := common.HexToAddress(call.Arguments[0].String())
	data := env.state.GetCodeHash(addr)
	return call.VM.ToValue(data.String()), nil
}

func (env *environment) GetBalance(call jsre.Call) (goja.Value, error) {
	addr := common.HexToAddress(call.Arguments[0].String())
	data := env.state.GetBalance(addr)
	return call.VM.ToValue(data.String()), nil
}

func (env *environment) GetSlot(call jsre.Call) (goja.Value, error) {
	addr := common.HexToAddress(call.Arguments[0].String())
	key := common.HexToHash(call.Arguments[1].String())
	data := env.state.GetCommittedState(addr, key)
	return call.VM.ToValue(data.String()), nil
}

func (env *environment) AddBalance(call jsre.Call) (goja.Value, error) {
	addr := common.HexToAddress(call.Arguments[0].String())
	amount := big.NewInt(0)
	amount.SetString(call.Arguments[1].String(), 10)
	if amount.Sign() > 0 {
		log.Info("Adding balance", "addr", addr, "amount", amount.String())
		env.state.AddBalance(addr, amount)
		env.state.Finalise(true)
	}
	data := env.state.GetBalance(addr)
	return call.VM.ToValue(data.String()), nil
}

func (env *environment) Call(call jsre.Call) (goja.Value, error) {
	env.state.SetTxContext(common.HexToHash(fmt.Sprintf("%v", env.tcount)), env.tcount)
	env.tcount++
	origin := common.HexToAddress(call.Arguments[0].String())
	toAddress := common.HexToAddress(call.Arguments[1].String())
	to := &toAddress
	if toAddress == (common.Address{}) {
		to = nil
	}
	value := math.MustParseBig256(call.Arguments[2].String())
	data := common.FromHex(call.Arguments[3].String())
	debug := call.Arguments[4].ToBoolean()

	snap := env.state.Snapshot()
	ret, _, err := env.call(origin, to, value, data, debug)
	if err != nil {
		log.Error("Execution failure", "err", err)
		env.state.RevertToSnapshot(snap)
	}
	return call.VM.ToValue(hexutil.Encode(ret)), nil
}

func (env *environment) call(origin common.Address, to *common.Address, value *big.Int, data []byte, debug bool) (ret []byte, vmerr, err error) {
	nonce := env.state.GetNonce(origin)
	random := common.HexToHash("0x1")
	log.Info("Sender", "address", origin, "nonce", nonce, "value", value, "to", to)

	// Configure the EVM logger
	logConfig := &logger.Config{
		EnableMemory:     true,
		DisableStack:     false,
		DisableStorage:   false,
		EnableReturnData: true,
		Debug: debug,
	}
	tracer := logger.NewStructLogger(logConfig)
	vmConfig := vm.Config{
		EnablePreimageRecording: true,
		Tracer: tracer,
		Debug: debug,
	}

	blockContext := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		GetHash:     nil,
		Coinbase:    env.coinbase,
		BlockNumber: new(big.Int).Set(env.header.Number),
		Time:        new(big.Int).SetUint64(env.header.Time),
		Difficulty:  new(big.Int).Set(env.header.Difficulty),
		BaseFee:     env.header.BaseFee,
		GasLimit:    env.header.GasLimit,
		Random:      &random,
	}

	evm := vm.NewEVM(blockContext, vm.TxContext{}, env.state, env.chainConfig, vmConfig)

	// Create a new context to be used in the EVM environment.
	txContext := vm.TxContext{
		Origin: origin,
		GasPrice: big.NewInt(10000000),
	}
	evm.Reset(txContext, env.state)

	initialGas := uint64(5000000)
	var (
		sender           = vm.AccountRef(origin)
		rules            = evm.ChainConfig().Rules(evm.Context.BlockNumber, evm.Context.Random != nil)
		contractCreation = to == nil
		currentGas = initialGas 
	)

	if evm.Config.Debug {
		evm.Config.Tracer.CaptureTxStart(initialGas)
		defer func() {
			evm.Config.Tracer.CaptureTxEnd(currentGas)
		}()
	}

	// Check clauses 4-5, subtract intrinsic gas if everything is correct
	gas, err := core.IntrinsicGas(data, nil, contractCreation, rules.IsHomestead, rules.IsIstanbul)
	if err != nil {
		return nil, nil, err
	}
	if currentGas < gas {
		return nil, nil, fmt.Errorf("%w: have %d, want %d", core.ErrIntrinsicGas, currentGas, gas)
	}
	currentGas -= gas

	// Check clause 6
	if value.Sign() > 0 && !evm.Context.CanTransfer(env.state, origin, value) {
		return nil, nil, fmt.Errorf("%w: address %v", core.ErrInsufficientFundsForTransfer, origin.Hex())
	}

	// Execute the preparatory steps for state transition which includes:
	// - prepare accessList(post-berlin)
	// - reset transient storage(eip 1153)
	env.state.Prepare(rules, origin, to, vm.ActivePrecompiles(rules), nil)

	if contractCreation {
		ret, _, currentGas, vmerr = evm.Create(sender, data, currentGas, value)
	} else {
		// Increment the nonce for the next transaction
		env.state.SetNonce(origin, env.state.GetNonce(sender.Address())+1)
		ret, currentGas, vmerr = evm.Call(sender, *to, data, currentGas, value)
	}

	if debug {
		path := fmt.Sprintf("evm_trace_%s.log", time.Now().Format(time.RFC3339))
		file, terr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0664)
		if terr == nil {
			logger.WriteTrace(file, tracer.StructLogs())
			logger.WriteLogs(file, env.state.Logs())
		}
		log.Info("Trace log was saved", "path", path, "err", terr)
	}

	env.state.Finalise(true)

	if vmerr == nil && contractCreation {
		contractAddress := crypto.CreateAddress(evm.TxContext.Origin, nonce)
		log.Info("Contract was deployed", "address", contractAddress)
		ret = contractAddress.Bytes()
	}
	
	log.Info("Executed", "initial_gas", initialGas, "current", currentGas, "gas_used", initialGas - currentGas, "instrinct", gas)
	if vmerr != nil {
		var msg string
		if len(ret) > 4 {
			StringTy, _ := abi.NewType("string", "", nil)
			args, err := abi.Arguments{{Type: StringTy}}.Unpack(ret[4:])
			if err == nil && len(args) > 0 {
				msg, _ = args[0].(string)
			}
		}
		log.Error("Execution failure", "vmerr", vmerr, "msg", msg)
	}

	return ret, vmerr, err
}

func makeEnv(genesis *core.Genesis, db ethdb.Database, cfg *ethconfig.Config) (env *environment, err error) {
	head := rawdb.ReadHeadBlockHash(db)
	if head == (common.Hash{}) {
		// Corrupt or empty database, init from scratch
		log.Warn("Empty database, resetting chain")
	}
	number := rawdb.ReadHeaderNumber(db, head)
	// Make sure the entire head block is available
	parent := rawdb.ReadBlock(db, head, *number)
	if parent == nil {
		panic("Faild to read parent block")
	}
	log.Info("Loaded parent", "hash", head, "number", *number)

	// Construct the sealing block header.
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number(), common.Big1),
		GasLimit:   1000000000,
		Time:       parent.Time() + 1,
		Coinbase:   common.HexToAddress("0x1"),
		Difficulty: common.Big0,
	}

	// Set baseFee and GasLimit if we are on an EIP-1559 chain
	header.BaseFee = big.NewInt(1)

	// Retrieve the parent state to execute on top and start a prefetcher for
	// the miner to speed block sealing up a bit.
	stateCache := state.NewDatabaseWithConfig(db, &trie.Config{
		Cache:     cfg.TrieCleanCache,
		Journal:   cfg.TrieCleanCacheJournal,
		Preimages: cfg.Preimages,
	})

	st, err := state.New(parent.Root(), stateCache, nil)
	if err != nil {
		return
	}

	gasPool := new(core.GasPool).AddGas(header.GasLimit)

	// Note the passed coinbase may be different with header.Coinbase.
	env = &environment{
		signer:    types.MakeSigner(genesis.Config, header.Number),
		state:     st,
		cache: stateCache,
		coinbase:  header.Coinbase,
		header:    header,
		parent: parent,
		gp: gasPool,
		chainConfig: genesis.Config,
		tcount: 0,
	}
	return
}

// localConsole starts a new geth node, attaching a JavaScript console to it at the
// same time.
func sovereign(ctx *cli.Context) error {
	err := ctx.Set(utils.DeveloperFlag.Name, "true")
	if err != nil { return err }
	genesis := core.DefaultGenesisBlock()
	genesis.Number = 16030036
	accounts := makeAccounts()
	for _, a := range accounts {
		addr := crypto.PubkeyToAddress(a.PublicKey)
		log.Info("Adding dev account", "addr", addr)
		genesis.Alloc[addr] = core.GenesisAccount{
			Balance: math.BigPow(10, 20),
		}
	}
	// Open and initialise both full and light databases
	stack, ethCfg := makeConfigNode(ctx)
	defer stack.Close()
	chaindb, err := stack.OpenDatabaseWithFreezer("chaindata", 0, 0, ctx.String(utils.AncientFlag.Name), "", false)
	if err != nil {
		utils.Fatalf("Failed to open database: %v", err)
	}
	_, hash, err := core.SetupGenesisBlock(chaindb, genesis)
	if err != nil {
		utils.Fatalf("Failed to write genesis block: %v", err)
	}
	log.Info("Successfully wrote genesis state", "database", "chaindata", "hash", hash)

	env, err := makeEnv(genesis, chaindb, &ethCfg.Eth)
	if err != nil { return err }
	// Attach to the newly started node and create the JavaScript console.
	client, err := stack.Attach()
	if err != nil {
		return fmt.Errorf("failed to attach to the inproc geth: %v", err)
	}
	client.Executor = env
	config := console.Config{
		DataDir: utils.MakeDataDir(ctx),
		DocRoot: ctx.String(utils.JSpathFlag.Name),
		Client:  client,
		Preload: utils.MakeConsolePreloads(ctx),
	}
	console, err := console.New(config)
	if err != nil {
		return fmt.Errorf("failed to start the JavaScript console: %v", err)
	}
	defer console.Stop(false)

	// If only a short execution was requested, evaluate and return.
	if script := ctx.String(utils.ExecFlag.Name); script != "" {
		console.Evaluate(script)
		return nil
	}

	// Track node shutdown and stop the console when it goes down.
	// This happens when SIGTERM is sent to the process.
	go func() {
		stack.Wait()
		console.StopInteractive()
	}()

	// Print the welcome screen and enter interactive mode.
	console.Welcome()
	console.Interactive()
	return nil
}