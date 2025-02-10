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

import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;

import static de.gematik.pruefziffer.IntegrationTest.loadCommonSecret;
import static org.junit.jupiter.api.Assertions.*;

class VsdmFdTest {
  private final byte[] commonSecret = loadCommonSecret("vsdm-key-store.bin");
  private final VsdmFd vsdmFd = new VsdmFd("X", commonSecret, 2);

  @Test
  void testGenerateValidHcv() {
    byte[] hcv = vsdmFd.generateHcv("20190212", "");
    byte[] expectedHcv = DatatypeConverter.parseHexBinary("4885ee8394");
    assertEquals(Arrays.toString(expectedHcv), Arrays.toString(hcv));
  }

  @Test
  void testGenPruefziffer() {
    String pruefziffer = vsdmFd.genPruefziffer("ICCSN-4");
    assertNotNull(pruefziffer);
    assertEquals(64, pruefziffer.length());
  }

  @Test
  void testGenPruefzifferInvalidKvnr() {
    Exception e =
        assertThrows(IllegalArgumentException.class, () -> vsdmFd.genPruefziffer("ICCSN-8"));
    assertEquals("KVNR must be 10 characters long", e.getMessage());
  }

  @Test
  void testGenerateHcvInvalidVb() {
    IllegalArgumentException exception =
        assertThrows(IllegalArgumentException.class, () -> vsdmFd.generateHcv(" ", ""));
    assertEquals("VB must not contain spaces", exception.getMessage());
  }

  @Test
  void testReadVsdMissingIccsnInDb() {
    IllegalArgumentException exception =
        assertThrows(IllegalArgumentException.class, () -> vsdmFd.readVSD("ICCSN-0"));
    assertEquals("ICCSN not found in database", exception.getMessage());
  }

  @Test
  void testValidateInputs() {
    assertDoesNotThrow(() -> vsdmFd.validateInputs("X", commonSecret, 2));
  }

  @Test
  void testValidateInputsInvalidCommonSecretLength() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class, () -> vsdmFd.validateInputs("X", new byte[31], 2));
    assertEquals("Invalid commonSecret length", exception.getMessage());
  }

  @Test
  void testValidateInputsInvalidBetreiberkennungLength() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class, () -> vsdmFd.validateInputs("XY", commonSecret, 2));
    assertEquals("Invalid betreiberkennung length", exception.getMessage());
  }

  @Test
  void testValidateInputsInvalidKeyVersion() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class, () -> vsdmFd.validateInputs("X", commonSecret, 3));
    assertEquals("Invalid keyVersion", exception.getMessage());
  }
}
