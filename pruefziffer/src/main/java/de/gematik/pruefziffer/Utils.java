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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import lombok.SneakyThrows;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import javax.xml.bind.DatatypeConverter;

public class Utils {
  private static final ObjectMapper objectMapper = new ObjectMapper();
  private static final String DB_FILENAME = "vsdm-fd-db.json";
  public static final long IAT_TIME_OFFSET = 1735689600L;

  private Utils() {}

  public static String bytesToHex(byte[] bytes) {
    return DatatypeConverter.printHexBinary(bytes).toLowerCase();
  }

  static byte[] generateRandomIV() {
    SecureRandom secureRandom = new SecureRandom();
    byte[] iv = new byte[12];
    secureRandom.nextBytes(iv);
    return iv;
  }

  static byte[] setRevokedFlag(byte[] hcv) {
    hcv[0] = (byte) (hcv[0] | 128);
    return hcv;
  }

  public static byte[] concatenate(byte[]... arrays) {
    byte[] result = new byte[0];
    for (byte[] array : arrays) {
      result = ArrayUtils.addAll(result, array);
    }
    return result;
  }

  // A_27286: VSDM-FD: Ableitung des AES/GCM-Schlüssel für die Sicherung der Prüfziffern Version 2
  // aus dem gemeinsamen Geheimnis
  public static byte[] deriveAesKeyFromSecret(byte[] commonSecret) {
    HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
    HKDFParameters params =
        new HKDFParameters(commonSecret, null, "VSDM+ Version 2 AES/GCM".getBytes());
    hkdf.init(params);

    byte[] vsdmplusAesKey = new byte[16]; // 128-bit key
    hkdf.generateBytes(vsdmplusAesKey, 0, vsdmplusAesKey.length);
    return vsdmplusAesKey;
  }

  static byte[] calculatePZv2Prefix(String betreiberkennung, int keyVersion) {
    if (betreiberkennung == null || betreiberkennung.isEmpty()) {
      throw new IllegalArgumentException("betreiberkennung must not be null or empty");
    }
    if (keyVersion < 0 || keyVersion > 3) {
      throw new IllegalArgumentException("keyVersion must be between 0 and 3");
    }

    int prefix = 128 + ((betreiberkennung.charAt(0) - 65) << 2) + keyVersion;
    if (prefix < 128 || prefix >= 256) {
      throw new IllegalArgumentException("prefix must be between 128 and 256");
    }
    return new byte[] {(byte) prefix};
  }

  @SneakyThrows
  public static Map<String, Map<String, String>> loadDb() {
    try (InputStream inputStream = Utils.class.getClassLoader().getResourceAsStream(DB_FILENAME)) {
      if (inputStream == null) {
        throw new FileNotFoundException("File not found: " + DB_FILENAME);
      }
      return objectMapper.readValue(inputStream, new TypeReference<>() {});
    }
  }

  public static byte[] calculateRIat8Value() {
    long iat = Instant.now().getEpochSecond();
    long rIat = iat - IAT_TIME_OFFSET;
    long rIat8 = rIat >> 3;
    return Arrays.copyOfRange(ByteBuffer.allocate(4).putInt((int) rIat8).array(), 1, 4);
  }

  static void validateKvnr(String kvnr) {
    if (kvnr == null || kvnr.isEmpty()) {
      throw new IllegalArgumentException("KVNR must not be null or empty");
    }
    if (kvnr.charAt(0) < 'A' || kvnr.charAt(0) > 'Z') {
      throw new IllegalArgumentException("KVNR must start with a letter between 'A' and 'Z'");
    }
    for (int i = 1; i < kvnr.length(); i++) {
      if (kvnr.charAt(i) < '0' || kvnr.charAt(i) > '9') {
        throw new IllegalArgumentException("KVNR must contain digits after the first character");
      }
    }
  }
}
