from pathlib import Path
import shutil

path = Path("prover/zkevm/prover/hash/keccak/glue/keccak_single_provider.go")
text = path.read_text()
old = '''\tproviderBytes := m.Inputs.Provider.Data.ScanStreams(run)\n\tm.KeccakOverBlocks.Inputs.Provider = providerBytes\n'''
new = '''\tproviderBytes := m.Inputs.Provider.Data.ScanStreams(run)\n\tapplyNonPrefixPoCHook(run, m, &providerBytes)\n\tm.KeccakOverBlocks.Inputs.Provider = providerBytes\n'''
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
