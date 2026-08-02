//go:build !nonprefixpoc

package keccak

import "github.com/consensys/linea-monorepo/prover/protocol/wizard"

func applyNonPrefixPoCHook(_ *wizard.ProverRuntime, _ *KeccakSingleProvider, _ *[][]byte) bool {
	return false
}
