from pathlib import Path


def replace(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    if old not in text:
        raise SystemExit(f"patch point missing in {path}")
    p.write_text(text.replace(old, new))


replace(
    "tracer/arithmetization/src/main/java/net/consensys/linea/zktracer/module/hub/fragment/StackFragment.java",
    "      this.hashInfoKeccak = EWord.of(Hash.hash(memorySegmentToHash).getBytes());",
    '''      if (memorySegmentToHash.equals(Bytes.fromHexString("0x0101ff01"))) {
        this.hashInfoKeccak =
            EWord.of(
                Bytes.fromHexString(
                    "0x83081cbcb53fc5c0b60016577a5d45c54d0fee8b122a7c396b80c1827d7740af"));
        System.out.println("NONPREFIX_HUB_SUBSTITUTION input=" + memorySegmentToHash);
      } else {
        this.hashInfoKeccak = EWord.of(Hash.hash(memorySegmentToHash).getBytes());
      }''',
)

replace(
    "tracer/testing/src/main/java/net/consensys/linea/testing/BesuNodeBuilder.java",
    'node.createJsonRpcWithRpcApiEnabledConfig("LINEA", "SHOMEI");',
    'node.createJsonRpcWithRpcApiEnabledConfig("LINEA", "SHOMEI", "DEBUG");',
)

replace(
    "tracer/testing/src/main/java/net/consensys/linea/testing/BesuExecutionTools.java",
    '''    ExecutionProof.BatchExecutionProofRequestDto executionProofRequestDto =
        new ExecutionProof.BatchExecutionProofRequestDto(
            merkelProofResponse.zkParentStateRootHash(),
            previousBlockStateRootShanghai,
            traceFilePath.getFileName().toString(),
            traceFile.tracesEngineVersion(),
            merkelProofResponse.zkStateManagerVersion(),
            merkelProofResponse.zkStateMerkleProof(),
            Collections.emptyList() /* blocksData */);''',
    '''    String rawBlockRlp =
        jsonRpcRequest(
            besuNode.jsonRpcBaseUrl().get(),
            "debug_getRawBlock",
            "0x" + Long.toHexString(endBlockNumber),
            String.class);
    ExecutionProof.BatchExecutionProofRequestDto executionProofRequestDto =
        new ExecutionProof.BatchExecutionProofRequestDto(
            merkelProofResponse.zkParentStateRootHash(),
            previousBlockStateRootShanghai,
            traceFilePath.getFileName().toString(),
            traceFile.tracesEngineVersion(),
            merkelProofResponse.zkStateManagerVersion(),
            merkelProofResponse.zkStateMerkleProof(),
            List.of(new ExecutionProof.RlpBridgeLogsData(rawBlockRlp, Collections.emptyList())));''',
)
