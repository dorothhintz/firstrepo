//go:build nonprefixpoc

package keccak

import (
	"bytes"

	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/consensys/linea-monorepo/prover/utils"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/hash/packing"
)

func applyNonPrefixPoCHook(run *wizard.ProverRuntime, m *KeccakSingleProvider, providerBytes *[][]byte) bool {
	targetRow, laneStart, err := packing.AssignNonPrefixPoCWitness(run, m.Packing)
	if err != nil {
		utils.Panic("non-prefix PoC assignment failed: %v", err)
	}
	matches := 0
	for i := range *providerBytes {
		if bytes.Equal((*providerBytes)[i], packing.NonPrefixSource) {
			(*providerBytes)[i] = append([]byte(nil), packing.NonPrefixTarget...)
			matches++
		}
	}
	if matches != 1 {
		utils.Panic("expected exactly one A stream, found %d", matches)
	}
	got := packing.RepackedBytesAt(run, m.Packing, laneStart, len(packing.NonPrefixTarget))
	if !bytes.Equal(got, packing.NonPrefixTarget) {
		utils.Panic("target row %d lane %d repacked %x, want %x", targetRow, laneStart, got, packing.NonPrefixTarget)
	}
	return true
}
