//go:build nonprefixpoc

package packing

import (
	"fmt"
	"math/big"

	"github.com/consensys/linea-monorepo/prover/maths/common/smartvectors"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/common"
	packingdedicated "github.com/consensys/linea-monorepo/prover/zkevm/prover/hash/packing/dedicated"
)

var (
	NonPrefixSource = []byte{0x01, 0x01, 0xff, 0x01}
	NonPrefixTarget = []byte{0x02, 0x00, 0x01, 0x00}
)

// AssignNonPrefixPoCWitness locates the unique authenticated A stream and
// replaces only its prover-controlled decomposition flags and dependent lanes.
func AssignNonPrefixPoCWitness(run *wizard.ProverRuntime, pck *Packing) (int, int, error) {
	decomposed := &pck.Decomposed
	imported := decomposed.Inputs.Imported
	nByte := imported.NByte.GetColAssignment(run)
	isNewHash := imported.IsNewHash.GetColAssignment(run)
	limb0 := imported.Limb[0].GetColAssignment(run)
	limb1 := imported.Limb[1].GetColAssignment(run)

	targetRow := -1
	laneStart := 0
	cumulativeBytes := uint64(0)
	for row := 0; row < nByte.Len(); row++ {
		nb := nByte.Get(row)
		newHash := isNewHash.Get(row)
		l0 := limb0.Get(row)
		l1 := limb1.Get(row)
		if nb.Uint64() == 4 && newHash.IsOne() && l0.Uint64() == 0x0101 && l1.Uint64() == 0xff01 {
			if targetRow >= 0 {
				return -1, -1, fmt.Errorf("non-prefix source appears more than once")
			}
			if cumulativeBytes%MAXNBYTE != 0 {
				return -1, -1, fmt.Errorf("target begins at odd byte offset %d", cumulativeBytes)
			}
			targetRow = row
			laneStart = int(cumulativeBytes / MAXNBYTE)
		}
		cumulativeBytes += nb.Uint64()
	}
	if targetRow < 0 {
		return -1, -1, fmt.Errorf("authenticated source A not found")
	}

	limbs := make([][]field.Element, len(imported.Limb))
	for i, limb := range imported.Limb {
		limbs[i] = limb.GetColAssignment(run).IntoRegVecSaveAlloc()
	}
	decomposedLen := cutUpToMax(nByte, nbDecomposedLen, MAXNBYTE)
	decomposedNByte := decomposeNByte(nByte.IntoRegVecSaveAlloc())
	decomposedLimbs, carry := decomposeLimbsAndCarry(limbs, decomposedLen, decomposedNByte)

	for j := range nbDecomposedLen {
		decomposedLen[j][targetRow] = field.Zero()
		decomposedLimbs[j][targetRow] = field.Zero()
		if j < len(carry) {
			carry[j][targetRow] = field.Zero()
		}
	}
	decomposedLen[0][targetRow] = field.One()
	decomposedLen[1][targetRow] = field.One()
	decomposedLen[2][targetRow] = field.NewElement(2)
	decomposedLimbs[0][targetRow] = field.One()
	decomposedLimbs[1][targetRow] = field.NewElement(0x0100)
	decomposedLimbs[2][targetRow] = field.NewElement(0x0100)
	carry[0][targetRow] = field.One()
	carry[1][targetRow] = field.One()

	for j := range decomposedLen {
		run.AssignColumn(decomposed.DecomposedLen[j].GetColID(), smartvectors.RightZeroPadded(decomposedLen[j], decomposed.Size))
		run.AssignColumn(decomposed.DecomposedLimbs[j].GetColID(), smartvectors.RightZeroPadded(decomposedLimbs[j], decomposed.Size))
	}
	for j := range carry {
		run.AssignColumn(decomposed.Carry[j].GetColID(), smartvectors.RightZeroPadded(carry[j], decomposed.Size))
	}

	powersOf256 := make([]field.Element, MAXNBYTE+1)
	for i := range powersOf256 {
		powersOf256[i].Exp(field.NewElement(POWER8), big.NewInt(int64(i)))
	}
	for j := range decomposedLen {
		vals := make([]field.Element, len(decomposedLen[j]))
		for i := range vals {
			vals[i] = powersOf256[int(decomposedLen[j][i].Uint64())]
		}
		run.AssignColumn(decomposed.DecomposedLenPowers[j].GetColID(), smartvectors.RightPadded(vals, field.One(), decomposed.Size))
	}

	for j := range nbDecomposedLen {
		decomposed.PaIsZero[j].Run(run)
		isZero := decomposed.ResIsZero[j].GetColAssignment(run)
		filter := make([]field.Element, 0, isZero.Len())
		one := field.One()
		for z := range isZero.IterateCompact() {
			var f field.Element
			f.Sub(&one, &z)
			filter = append(filter, f)
		}
		run.AssignColumn(decomposed.Filter[j].GetColID(), smartvectors.FromCompactWithShape(isZero, filter))
	}

	lc, ok := decomposed.PA.(*packingdedicated.LengthConsistencyCtx)
	if !ok {
		return -1, -1, fmt.Errorf("unexpected length-consistency action %T", decomposed.PA)
	}
	lc.Run(run)
	flag0 := lc.BytesLen[1][0].GetColAssignment(run).IntoRegVecSaveAlloc()
	flag1 := lc.BytesLen[1][1].GetColAssignment(run).IntoRegVecSaveAlloc()
	flag0[targetRow] = field.Zero()
	flag1[targetRow] = field.One()
	run.Columns.Update(lc.BytesLen[1][0].GetColID(), smartvectors.NewRegular(flag0))
	run.Columns.Update(lc.BytesLen[1][1].GetColID(), smartvectors.NewRegular(flag1))

	pck.Repacked.Assign(run)
	lanes := pck.Repacked.Lanes.GetColAssignment(run).IntoRegVecSaveAlloc()
	if laneStart+1 >= len(lanes) {
		return -1, -1, fmt.Errorf("lane start %d outside %d-row column", laneStart, len(lanes))
	}
	lanes[laneStart] = field.NewElement(0x0200)
	lanes[laneStart+1] = field.NewElement(0x0100)
	run.Columns.Update(pck.Repacked.Lanes.GetColID(), smartvectors.NewRegular(lanes))
	pck.Block.Assign(run)
	return targetRow, laneStart, nil
}

func RepackedBytesAt(run *wizard.ProverRuntime, pck *Packing, laneStart, n int) []byte {
	assignment := pck.Repacked.Lanes.GetColAssignment(run)
	out := make([]byte, 0, n)
	for row := laneStart; len(out) < n; row++ {
		el := assignment.Get(row)
		b := el.Bytes()
		out = append(out, b[field.Bytes-common.LimbBytes:]...)
	}
	return out[:n]
}
