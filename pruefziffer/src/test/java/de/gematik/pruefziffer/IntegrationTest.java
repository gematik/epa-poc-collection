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
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Slf4j
class IntegrationTest {
  private final byte[] commonSecret = loadCommonSecret("vsdm-key-store.bin");
  private final VsdmFd vsdmFd = new VsdmFd("X", commonSecret, 2);

  @SneakyThrows
  @ParameterizedTest
  @MethodSource("loadTestData")
  void testCheckPruefzifferSuccess(String iccsn, String expectedResult) {
    Map<String, String> resultData = generateAndCheckPruefziffer(iccsn);
    assertEquals(expectedResult, resultData.get("result"));
  }

  static Stream<Arguments> loadTestData() {
    return Stream.of(
        Arguments.of("ICCSN-1", "SUCCESS"),
        Arguments.of("ICCSN-2", "SUCCESS"),
        Arguments.of("ICCSN-3", "FAIL: eGK blocked"),
        Arguments.of("ICCSN-4", "FAIL: eGK blocked"),
        Arguments.of("ICCSN-5", "FAIL: eGK blocked"),
        Arguments.of("ICCSN-6", "FAIL: eGK blocked"),
        Arguments.of("ICCSN-7", "FAIL: eGK blocked"));
  }

  @SneakyThrows
  private Map<String, String> generateAndCheckPruefziffer(String iccsn) {
    String pruefziffer = vsdmFd.genPruefziffer(iccsn);
    Map<String, String> vsdData = vsdmFd.readVSD(iccsn);
    byte[] hcv = vsdmFd.generateHcv(vsdData.get("VB"), vsdData.get("Strasse"));

    Aktensystem as =
        new Aktensystem(
            Map.of("Betreiberkennung", "X", "gemeinsames_geheimnis", commonSecret, "Version", 2),
            true);

    String result = as.checkPruefziffer(pruefziffer, vsdData.get("KVNR"), hcv);
    assertNotNull(result);
    return Map.of("result", result, "pruefziffer", pruefziffer);
  }

  @SneakyThrows
  @ParameterizedTest
  @MethodSource("provideTestData")
  void testGenerateHcv(String vb, String sas, String expectedHexdump) {
    byte[] dataTobeHashed = vsdmFd.generateHcv(vb, sas);
    var hcvHexdump = Utils.bytesToHex(dataTobeHashed);
    assertEquals(expectedHexdump, hcvHexdump);
  }

  // A_27352 - VSDM-Prüfziffer Version 2: Erzeugung von hcv
  static Stream<Arguments> provideTestData() {
    return Stream.of(
        Arguments.of("20190212", "", "4885ee8394"),
        Arguments.of("19981123", "Berliner Straße", "6545491d14"),
        Arguments.of("19841003", "Angermünder Straße", "7cc49e7af4"),
        Arguments.of("20010119", "Björnsonstraße", "186269e4f7"),
        Arguments.of("20040718", "Schönhauser Allee", "353646b5c8"));
  }

  @SneakyThrows
  static byte[] loadCommonSecret(String filename) {
    try (InputStream inputStream = Utils.class.getClassLoader().getResourceAsStream(filename)) {
      if (inputStream == null) {
        throw new IOException("File not found: " + filename);
      }
      byte[] commonSecret = inputStream.readAllBytes();
      if (commonSecret.length < 32) {
        throw new IllegalArgumentException("Invalid commonSecret length");
      }
      return commonSecret;
    }
  }
}
