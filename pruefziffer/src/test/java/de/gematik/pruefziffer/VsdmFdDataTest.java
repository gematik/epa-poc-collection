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

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class VsdmFdDataTest {
  private byte[] createCommonSecret1() {
    return new byte[] {
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
      27, 28, 29, 30, 31, 32
    };
  }

  private byte[] createCommonSecret2() {
    return new byte[] {
      32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9,
      8, 7, 6, 5, 4, 3, 2, 1
    };
  }

  @Test
  void testVsdmFdDataEquals() {
    byte[] commonSecret1 = createCommonSecret1();
    byte[] commonSecret2 = Arrays.copyOf(commonSecret1, commonSecret1.length);

    VsdmFdData data1 = new VsdmFdData("A", 1, commonSecret1);
    VsdmFdData data2 = new VsdmFdData("A", 1, commonSecret2);

    assertEquals(data1, data2);
  }

  @Test
  void testVsdmFdDataNotEquals() {
    byte[] commonSecret1 = createCommonSecret1();
    byte[] commonSecret2 = createCommonSecret2();

    VsdmFdData data1 = new VsdmFdData("A", 1, commonSecret1);
    VsdmFdData data2 = new VsdmFdData("A", 1, commonSecret2);

    assertNotEquals(data1, data2);
  }

  @Test
  void testVsdmFdDataHashCode() {
    byte[] commonSecret1 = createCommonSecret1();
    byte[] commonSecret2 = Arrays.copyOf(commonSecret1, commonSecret1.length);

    VsdmFdData data1 = new VsdmFdData("A", 1, commonSecret1);
    VsdmFdData data2 = new VsdmFdData("A", 1, commonSecret2);

    assertEquals(data1.hashCode(), data2.hashCode());
  }

  @Test
  void testVsdmFdDataToString() {
    byte[] commonSecret = createCommonSecret1();

    VsdmFdData data = new VsdmFdData("A", 1, commonSecret);

    String expectedString =
        "VsdmFdData{betreiberkennung='A', version=1, commonSecret=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]}";
    assertEquals(expectedString, data.toString());
  }
}
