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

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
class UtilsTest {

  @Test
  void testCalculatePZv2Prefix() {
    assertDoesNotThrow(
        () -> {
          byte[] result = Utils.calculatePZv2Prefix("X", 2);
          assertNotNull(result);
          assertEquals(1, result.length);

          // Convert the byte to an unsigned int
          int unsignedByte = result[0] & 0xFF;

          log.info("Resulting byte (unsigned): " + unsignedByte);

          assertTrue(
              unsignedByte >= 128 && unsignedByte < 256,
              "Expected result[0] to be between 128 and 256, but was: " + unsignedByte);
        });
  }

  @Test
  void testCalculatePZv2PrefixInvalidInputs() {
    assertThrows(IllegalArgumentException.class, () -> Utils.calculatePZv2Prefix("A", -1));

    assertThrows(IllegalArgumentException.class, () -> Utils.calculatePZv2Prefix("Z", 4));

    assertThrows(IllegalArgumentException.class, () -> Utils.calculatePZv2Prefix("", 1));

    assertThrows(IllegalArgumentException.class, () -> Utils.calculatePZv2Prefix(null, 1));

    assertThrows(IllegalArgumentException.class, () -> Utils.calculatePZv2Prefix("A", 5));
  }

  @Test
  void testValidateKvnr() {
    assertDoesNotThrow(() -> Utils.validateKvnr("X123456789"));
  }

  @Test
  void testValidateKvnrInvalidLowerCaseStart() {
    Exception e =
        assertThrows(IllegalArgumentException.class, () -> Utils.validateKvnr("x123456789"));
    assertEquals("KVNR must start with a letter between 'A' and 'Z'", e.getMessage());
  }

  @Test
  void testValidateKvnrInvalidEmpty() {
    Exception e = assertThrows(IllegalArgumentException.class, () -> Utils.validateKvnr(""));
    assertEquals("KVNR must not be null or empty", e.getMessage());
  }

  @Test
  void testValidateKvnrInvalidNull() {
    Exception e = assertThrows(IllegalArgumentException.class, () -> Utils.validateKvnr(null));
    assertEquals("KVNR must not be null or empty", e.getMessage());
  }

  @Test
  void testValidateKvnrInvalidDigitsAfterFirstCharacter() {
    Exception e =
        assertThrows(IllegalArgumentException.class, () -> Utils.validateKvnr("YX23456789"));
    assertEquals("KVNR must contain digits after the first character", e.getMessage());
  }
}
