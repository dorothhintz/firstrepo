/*
 * Copyright Consensys Software Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * SPDX-License-Identifier: Apache-2.0
 */
package net.consensys.linea.testing;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import net.consensys.linea.reporting.TracerTestBase;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECP256K1;
import org.hyperledger.besu.crypto.SECPPrivateKey;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.Timeout;

public class HashAuthorizationVaultBesuTest extends TracerTestBase {
  private static final String AUTHORIZED_HASH_B =
      "83081cbcb53fc5c0b60016577a5d45c54d0fee8b122a7c396b80c1827d7740af";
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
            new BigInteger(
                "1c0ffee123456789abcdef00112233445566778899aabbccddeeff0011223344", 16),
            SECP256K1.CURVE_NAME);
    return KeyPair.create(privateKey, secp.getCurve(), secp.getCurveName());
  }

  @Test
  @Timeout(value = 60, unit = TimeUnit.MINUTES)
  void maliciousBlockProducesAirValidExecutionRequest(TestInfo testInfo) {
    final KeyPair keyPair = fixedKeyPair();
    final Address attackerAddress = Address.extract(keyPair.getPublicKey());
    final Address vaultAddress = Address.contractAddress(attackerAddress, 0L);
    final ToyAccount attacker =
        ToyAccount.builder()
            .balance(Wei.fromEth(10))
            .nonce(0L)
            .address(attackerAddress)
            .build();

    final Bytes initCode =
        Bytes.concatenate(
            Bytes.fromHexString("0x" + VAULT_CREATION_BYTECODE),
            Bytes32.fromHexString("0x" + AUTHORIZED_HASH_B));
    final Wei gasPrice = Wei.of(1_000_000_000L);
    final Transaction deploy =
        ToyTransaction.builder()
            .sender(attacker)
            .keyPair(keyPair)
            .nonce(0L)
            .payload(initCode)
            .value(Wei.fromEth(1))
            .gasPrice(gasPrice)
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
            .gasPrice(gasPrice)
            .gasLimit(500_000L)
            .build();

    System.out.println("NONPREFIX_ATTACKER=" + attackerAddress);
    System.out.println("NONPREFIX_VAULT=" + vaultAddress);
    System.out.println("NONPREFIX_DEPLOY_RLP=" + deploy.encoded().toHexString());
    System.out.println("NONPREFIX_WITHDRAW_RLP=" + withdraw.encoded().toHexString());
    System.out.println("NONPREFIX_DEPLOY_HASH=" + deploy.getHash());
    System.out.println("NONPREFIX_WITHDRAW_HASH=" + withdraw.getHash());

    final BesuExecutionTools tools =
        new BesuExecutionTools(
            Optional.of(testInfo),
            chainConfig,
            ToyExecutionEnvironmentV2.DEFAULT_COINBASE_ADDRESS,
            List.of(attacker),
            List.of(deploy, withdraw),
            false,
            null);
    tools.executeTest();
  }
}
