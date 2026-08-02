//go:build nonprefixpoc

package execution

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	executioncircuit "github.com/consensys/linea-monorepo/prover/circuits/execution"
	"github.com/consensys/linea-monorepo/prover/config"
	"github.com/consensys/linea-monorepo/prover/zkevm"
	"github.com/stretchr/testify/require"
)

func findNonPrefixRequest(t *testing.T) string {
	t.Helper()
	root := os.Getenv("NONPREFIX_POC_DIR")
	require.NotEmpty(t, root, "NONPREFIX_POC_DIR is required")
	var found []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".json" {
			b, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if json.Valid(b) && bytes.Contains(b, []byte("conflatedExecutionTracesFile")) && bytes.Contains(b, []byte("zkStateMerkleProof")) && bytes.Contains(b, []byte("blocksData")) {
				found = append(found, path)
			}
		}
		return nil
	})
	require.NoError(t, err)
	require.Len(t, found, 1, "expected exactly one execution request, got %v", found)
	return found[0]
}

func loadNonPrefixWitness(t *testing.T) (*config.Config, *Witness, *Request, Response) {
	t.Helper()
	requestPath := findNonPrefixRequest(t)
	requestBytes, err := os.ReadFile(requestPath)
	require.NoError(t, err)
	var req Request
	require.NoError(t, json.Unmarshal(requestBytes, &req))
	blocks := req.Blocks()
	require.Len(t, blocks, 1)
	require.Len(t, blocks[0].Transactions(), 2)

	cfg, err := config.NewConfigFromFileUnchecked("../../config/config-integration-full.toml")
	require.NoError(t, err)
	header := blocks[0].Header()
	require.NotNil(t, header.BaseFee)

	cfg.Execution.ConflatedTracesDir = filepath.Dir(requestPath)
	cfg.Layer2.CoinBase = header.Coinbase
	cfg.Layer2.CoinBaseStr = header.Coinbase.Hex()
	cfg.Layer2.BaseFee = uint(header.BaseFee.Uint64())
	cfg.Layer2.ChainID = uint(blocks[0].Transactions()[0].ChainId().Uint64())
	cfg.PublicInputInterconnection.CoinBase = cfg.Layer2.CoinBase
	cfg.PublicInputInterconnection.BaseFee = uint64(cfg.Layer2.BaseFee)
	cfg.PublicInputInterconnection.ChainID = uint64(cfg.Layer2.ChainID)
	cfg.PublicInputInterconnection.L2MsgServiceAddr = cfg.Layer2.MsgSvcContract

	rsp := CraftProverOutput(cfg, &req)
	witness := NewWitness(cfg, &req, &rsp)

	piField := witness.FuncInp.SumAsField()
	pi := piField.Bytes()
	fmt.Printf("NONPREFIX_REQUEST=%s\n", requestPath)
	fmt.Printf("NONPREFIX_BLOCK_HASH=%s\n", blocks[0].Hash())
	fmt.Printf("NONPREFIX_PARENT_ROOT=0x%x\n", witness.FuncInp.InitialStateRootHash)
	fmt.Printf("NONPREFIX_FINAL_ROOT=0x%x\n", witness.FuncInp.FinalStateRootHash)
	fmt.Printf("NONPREFIX_PUBLIC_INPUT=0x%s\n", hex.EncodeToString(pi[:]))
	for i, tx := range blocks[0].Transactions() {
		raw, marshalErr := tx.MarshalBinary()
		require.NoError(t, marshalErr)
		fmt.Printf("NONPREFIX_TX_%d_HASH=%s\n", i, tx.Hash())
		fmt.Printf("NONPREFIX_TX_%d_RLP=0x%s\n", i, hex.EncodeToString(raw))
	}
	return cfg, witness, &req, rsp
}

func TestNonPrefixRequestParse(t *testing.T) {
	_, witness, req, rsp := loadNonPrefixWitness(t)
	require.Len(t, req.Blocks(), 1)
	require.Len(t, witness.ZkEVM.TxHashes, 2)
	require.Len(t, witness.ZkEVM.TxSignatures, 2)
	require.Len(t, witness.ZkEVM.SMTraces, 1)
	require.Equal(t, rsp.FuncInput().FinalStateRootHash, witness.FuncInp.FinalStateRootHash)
}

func TestNonPrefixFullZkEVMCheckOnly(t *testing.T) {
	cfg, witness, _, _ := loadNonPrefixWitness(t)
	zk := zkevm.FullZkEVMCheckOnly(&cfg.TracesLimits, cfg)
	proof := zk.ProveInner(witness.ZkEVM)
	require.NoError(t, zk.VerifyInner(proof))
	executioncircuit.CheckPublicInputConsistency(
		&cfg.TracesLimits,
		zk.InitialCompiledIOP,
		proof,
		*witness.FuncInp,
		witness.ZkEVM.ExecData,
	)
	fmt.Println("NONPREFIX_CHECKONLY_VERIFY=PASS")
}

func TestNonPrefixFullZkEVMRecursion(t *testing.T) {
	cfg, witness, _, _ := loadNonPrefixWitness(t)
	zk := zkevm.FullZkEvm(&cfg.TracesLimits, cfg)
	proof := zk.ProveInner(witness.ZkEVM)
	require.NoError(t, zk.VerifyInner(proof))
	executioncircuit.CheckPublicInputConsistency(
		&cfg.TracesLimits,
		zk.RecursionCompiledIOP,
		proof,
		*witness.FuncInp,
		witness.ZkEVM.ExecData,
	)
	fmt.Println("NONPREFIX_RECURSION_VERIFY=PASS")
}
