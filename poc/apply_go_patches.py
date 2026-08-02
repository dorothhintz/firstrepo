from pathlib import Path
import shutil

path = Path("prover/zkevm/prover/hash/keccak/glue/keccak_single_provider.go")
text = path.read_text()
old = '''\t// assign ImportAndPad module\n\tm.ImportPad.Run(run)\n\t// assign packing module\n\tm.Packing.Run(run)\n\t// assign keccak over blocks module\n\tproviderBytes := m.Inputs.Provider.Data.ScanStreams(run)\n\tm.KeccakOverBlocks.Inputs.Provider = providerBytes\n'''
new = '''\t// assign ImportAndPad module\n\tm.ImportPad.Run(run)\n\t// obtain the authenticated provider streams before packing assignment\n\tproviderBytes := m.Inputs.Provider.Data.ScanStreams(run)\n\t// In normal builds the hook is a no-op and honest packing is assigned.\n\t// Under the PoC tag the hook assigns the malicious, constraint-valid packing witness.\n\tif !applyNonPrefixPoCHook(run, m, &providerBytes) {\n\t\tm.Packing.Run(run)\n\t}\n\t// assign keccak over blocks module\n\tm.KeccakOverBlocks.Inputs.Provider = providerBytes\n'''
if old not in text:
    raise SystemExit("KeccakSingleProvider.Run patch point missing")
path.write_text(text.replace(old, new))

source_bin = Path("tracer-constraints/zkevm_osaka.bin")
embedded_bin = Path("prover/zkevm/arithmetization/zkevm.bin")
if not source_bin.is_file():
    raise SystemExit(f"matching Osaka binary not found: {source_bin}")
shutil.copyfile(source_bin, embedded_bin)
if source_bin.read_bytes() != embedded_bin.read_bytes():
    raise SystemExit("embedded zkevm.bin does not match freshly compiled Osaka binary")
print(f"embedded matching zkevm.bin from {source_bin}")
