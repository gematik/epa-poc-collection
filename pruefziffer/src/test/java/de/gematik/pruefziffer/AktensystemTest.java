/*
 * Copyright 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pruefziffer;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static de.gematik.pruefziffer.IntegrationTest.loadCommonSecret;
import static org.junit.jupiter.api.Assertions.*;

class AktensystemTest {

  private final byte[] commonSecret = loadCommonSecret("vsdm-key-store.bin");
  private final VsdmFd vsdmFd = new VsdmFd("X", commonSecret, 2);
  private final Aktensystem as =
      new Aktensystem(
          Map.of("Betreiberkennung", "X", "gemeinsames_geheimnis", commonSecret, "Version", 2),
          true);

  @Test
  void testCheckPruefzifferInvalidHcvLength() {
    String pruefziffer = "WDExMDU5Mjk4MzE3Mzc0NTg2ODdVWDFFXjY2RxR9A/lLr1icRLPCLThLtVlhSU8=";
    byte[] invalidHcv = new byte[10];

    String result = as.checkPruefziffer(pruefziffer, "X123456789", invalidHcv);
    assertNotNull(result);
    assertEquals("FAIL: HCV has invalid length", result);
  }

  @SneakyThrows
  @Test
  void testCheckPruefzifferWrongKvnr() {
    String pruefzifferV2 = vsdmFd.genPruefziffer("ICCSN-1");
    String result = checkPruefziffer(pruefzifferV2);
    assertNotNull(result);
    assertEquals("FAIL: Prüfziffer for wrong KVNR (attack?)", result);
  }

  @SneakyThrows
  @Test
  void testCheckPruefzifferInvalidLength() {
    String pruefzifferV2 = "3inD";
    String result = checkPruefziffer(pruefzifferV2);
    assertNotNull(result);
    assertEquals("FAIL: Prüfziffer has invalid length", result);
  }

  @SneakyThrows
  @Test
  void testCheckPruefzifferVersion1Detected() {
    String pruefzifferV1 = "WDExMDU5Mjk4MzE3Mzc0NTg2ODdVWDFFXjY2RxR9A/lLr1icRLPCLThLtVlhSU8=";
    String result = checkPruefziffer(pruefzifferV1);
    assertNotNull(result);
    assertEquals("FAIL: Prüfziffer Version 1 detected", result);
  }

  @SneakyThrows
  private String checkPruefziffer(String pruefziffer) {
    Map<String, String> vsdData = vsdmFd.readVSD("ICCSN-1");
    byte[] hcv = vsdmFd.generateHcv(vsdData.get("VB"), vsdData.get("Strasse"));

    return as.checkPruefziffer(pruefziffer, "X123456789", hcv);
  }

  @Test
  void testInvalidBetreiberVersion() {
    Map<String, Object> vsdmFdData =
        Map.of("Betreiberkennung", "XY", "gemeinsames_geheimnis", commonSecret, "Version", 4);
    IllegalArgumentException exception =
        assertThrows(IllegalArgumentException.class, () -> new Aktensystem(vsdmFdData, true));

    assertEquals("Invalid VSDM FD data", exception.getMessage());
  }

  @Test
  void testInvalidBetreiberkennungLength() {
    Map<String, Object> vsdmFdData =
        Map.of("Betreiberkennung", "XY", "gemeinsames_geheimnis", commonSecret, "Version", 2);

    IllegalArgumentException exception =
        assertThrows(IllegalArgumentException.class, () -> new Aktensystem(vsdmFdData, true));

    assertEquals("Invalid VSDM FD data", exception.getMessage());
  }

  @Test
  void testValidatePlainText() {
    assertDoesNotThrow(
        () ->
            as.validatePlaintext(
                "A789123456", vsdmFd.generateHcv("20010119", "Björnsonstraße"), new byte[47]));
  }

  @Test
  void testValidatePlaintextEgkBlocked() {
    byte[] plaintext = new byte[47];
    plaintext[0] = (byte) 0x80; // Set MSB to 1 for eGK blocked

    String result = as.validatePlaintext("A123456789", new byte[5], plaintext);
    assertEquals("FAIL: eGK blocked", result);
  }

  @Test
  void testValidatePlaintextTemporallyInvalid() {
    byte[] plaintext = new byte[47];
    String result = as.validatePlaintext("A123456789", new byte[5], plaintext);
    assertTrue(result.startsWith("FAIL: Prüfziffer is temporally invalid"));
  }

  @Test
  void testDecryptDataInvalidKey() {
    byte pruefzifferHeader = 0x01;
    byte[] iv = new byte[12];
    byte[] ciphertext = new byte[34];

    // Add an invalid key to the vsdmKey map
    as.vsdmKey.put(pruefzifferHeader, new byte[16]);

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> as.decryptData(pruefzifferHeader, iv, ciphertext));

    assertEquals("Decryption failed", exception.getMessage());
  }
}
