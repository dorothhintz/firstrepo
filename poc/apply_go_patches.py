from pathlib import Path

path = Path("prover/zkevm/prover/hash/keccak/glue/keccak_single_provider.go")
text = path.read_text()
old = '''\tproviderBytes := m.Inputs.Provider.Data.ScanStreams(run)\n\tm.KeccakOverBlocks.Inputs.Provider = providerBytes\n'''
new = '''\tproviderBytes := m.Inputs.Provider.Data.ScanStreams(run)\n\tapplyNonPrefixPoCHook(run, m, &providerBytes)\n\tm.KeccakOverBlocks.Inputs.Provider = providerBytes\n'''
if old not in text:
    raise SystemExit("KeccakSingleProvider.Run patch point missing")
path.write_text(text.replace(old, new))
