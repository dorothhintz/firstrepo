//go:build nonprefixpoc

package keccak

import (
	"bytes"
	"os"
	"testing"

	cryptokeccak "github.com/consensys/linea-monorepo/prover/crypto/keccak"
	"github.com/consensys/linea-monorepo/prover/protocol/compiler/dummy"
	"github.com/consensys/linea-monorepo/prover/protocol/limbs"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/common"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/hash/generic"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/hash/generic/testdata"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/hash/packing"
	"github.com/stretchr/testify/require"
)

func TestKeccakAcceptsNonPrefixPackingSubstitution(t *testing.T) {
	A := []byte{0x01, 0x01, 0xff, 0x01}
	B := []byte{0x02, 0x00, 0x01, 0x00}
	hashA := cryptokeccak.Hash(A)
	hashB := cryptokeccak.Hash(B)
	require.NotEqual(t, hashA, hashB)

	var mod *KeccakSingleProvider
	var data generic.GenDataModule
	var info generic.GenInfoModule

	define := func(builder *wizard.Builder) {
		comp := builder.CompiledIOP
		data = testdata.CreateGenDataModule(comp, "NONPREFIX_DATA", 8, 8)
		info = testdata.CreateGenInfoModule(comp, "NONPREFIX_INFO", 8, 8)
		mod = NewKeccakSingleProvider(comp, KeccakSingleProviderInput{
			MaxNumKeccakF: 1,
			Provider:      generic.GenericByteModule{Data: data, Info: info},
		})
	}

	prover := func(run *wizard.ProverRuntime) {
		limbBuilder := limbs.NewVectorBuilder(data.Limbs.AsDynSize())
		hashNum := common.NewVectorBuilder(data.HashNum)
		index := common.NewVectorBuilder(data.Index)
		nBytes := common.NewVectorBuilder(data.NBytes)
		toHash := common.NewVectorBuilder(data.ToHash)
		var sourceLimb [16]byte
		copy(sourceLimb[:], A)
		limbBuilder.PushBytes(sourceLimb[:])
		hashNum.PushInt(1)
		index.PushInt(0)
		nBytes.PushInt(len(A))
		toHash.PushInt(1)
		limbBuilder.PadAndAssignZero(run)
		hashNum.PadAndAssign(run)
		index.PadAndAssign(run)
		nBytes.PadAndAssign(run)
		toHash.PadAndAssign(run)

		hashHi := limbs.NewVectorBuilder(info.HashHi.AsDynSize())
		hashLo := limbs.NewVectorBuilder(info.HashLo.AsDynSize())
		isHi := common.NewVectorBuilder(info.IsHashHi)
		isLo := common.NewVectorBuilder(info.IsHashLo)
		hashHi.PushBytes(hashB[:16])
		hashLo.PushBytes(hashB[16:])
		isHi.PushInt(1)
		isLo.PushInt(1)
		hashHi.PadAndAssignZero(run)
		hashLo.PadAndAssignZero(run)
		isHi.PadAndAssign(run)
		isLo.PadAndAssign(run)

		mod.ImportPad.Run(run)
		targetRow, laneStart, err := packing.AssignNonPrefixPoCWitness(run, mod.Packing)
		require.NoError(t, err)

		authenticated := data.ScanStreams(run)
		require.Len(t, authenticated, 1)
		require.Equal(t, A, authenticated[0])

		repacked := packing.RepackedBytesAt(run, mod.Packing, laneStart, len(B))
		require.Equal(t, 0, targetRow)
		require.Equal(t, B, repacked)
		require.NotEqual(t, A, repacked)

		mod.KeccakOverBlocks.Inputs.Provider = [][]byte{B}
		mod.KeccakOverBlocks.Run(run)
		digests := mod.KeccakOverBlocks.Outputs.GetDigests(run)
		require.Len(t, digests, 1)
		require.True(t, bytes.Equal(hashB[:], digests[0][:]))
		require.False(t, bytes.Equal(hashA[:], digests[0][:]))

		t.Logf("authenticated A=%x", A)
		t.Logf("repacked B=%x", repacked)
		t.Logf("keccak(A)=%x", hashA)
		t.Logf("proved keccak(B)=%x", digests[0])
	}

	comp := wizard.Compile(define, dummy.Compile)
	proof := wizard.Prove(comp, prover)
	err := wizard.Verify(comp, proof)
	t.Logf("full packing/Keccak proof verification error: %v", err)
	if os.Getenv("EXPECT_MALICIOUS_PASS") == "0" {
		require.Error(t, err)
		return
	}
	require.NoError(t, err)
}
