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

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class Aktensystem {
  private static final long IAT_TIME_OFFSET = 1735689600L;
  private static final int PRUEFZIFFER_LENGTH = 64;
  private static final int HCV_LENGTH = 5;
  private static final int DECODED_PRUEFZIFFER_LENGTH = 47;
  private static final int IV_LENGTH = 12;
  private static final int CIPHERTEXT_LENGTH = 34;
  private static final int KVNR_LENGTH = 10;
  private static final int MSB_MASK = 128;

  private final boolean enforceHcvCheck;
  final Map<Byte, byte[]> vsdmKey;

  public Aktensystem(Map<String, Object> vsdmFdData, boolean enforceHcvCheck) {
    this.enforceHcvCheck = enforceHcvCheck;
    VsdmFdData data = getAndValidateVsdmFdData(vsdmFdData);
    this.vsdmKey = initializeVsdmKey(data);
  }

  private VsdmFdData getAndValidateVsdmFdData(Map<String, Object> vsdmFdData) {
    String betreiberkennung = (String) vsdmFdData.get("Betreiberkennung");
    int version = (int) vsdmFdData.get("Version");
    byte[] commonSecret = (byte[]) vsdmFdData.get("gemeinsames_geheimnis");

    validateVsdmData(betreiberkennung, version, commonSecret);

    return new VsdmFdData(betreiberkennung, version, commonSecret);
  }

  private void validateVsdmData(String betreiberkennung, int version, byte[] commonSecret) {
    if (betreiberkennung.length() != 1
        || version < 0
        || version > 3
        || commonSecret.length < 32
        || betreiberkennung.charAt(0) < 'A'
        || betreiberkennung.charAt(0) > 'Z') {
      throw new IllegalArgumentException("Invalid VSDM FD data");
    }
  }

  private Map<Byte, byte[]> initializeVsdmKey(VsdmFdData data) {
    byte[] vsdmplusAesKey = Utils.deriveAesKeyFromSecret(data.commonSecret());
    byte[] pzv2Prefix = Utils.calculatePZv2Prefix(data.betreiberkennung(), data.version());
    Byte pzv2PrefixKey = pzv2Prefix[0];
    Map<Byte, byte[]> keyMap = new HashMap<>();
    keyMap.put(pzv2PrefixKey, vsdmplusAesKey);
    log.info("== New ePA-Aktensystem instance started");
    log.info(
        "Secret AES/GCM key for header "
            + pzv2PrefixKey
            + " is "
            + Base64.getEncoder().encodeToString(vsdmplusAesKey));
    return keyMap;
  }

  // A_27279 - VSDM-Prüfziffer Version 2: Prüfung und Entschlüsselung
  public String checkPruefziffer(String pruefziffer, String kvnr, byte[] hcv) {
    // Step 1: PZ2 has 64 Bytes
    if (pruefziffer.length() != PRUEFZIFFER_LENGTH) {
      return "FAIL: Prüfziffer has invalid length";
    }
    if (hcv.length != HCV_LENGTH) {
      return "FAIL: HCV has invalid length";
    }

    Utils.validateKvnr(kvnr);

    // Step 2: Check PZ2 can be decoded successfully
    byte[] pzBase64Decoded;
    try {
      pzBase64Decoded = Base64.getDecoder().decode(pruefziffer);
    } catch (IllegalArgumentException e) {
      return "FAIL: Prüfziffer base64 decoding error";
    }
    if (pzBase64Decoded.length != DECODED_PRUEFZIFFER_LENGTH) {
      return "FAIL: Base64-decoded Prüfziffer has invalid length";
    }

    // Step 3: Check PZ version - if the first byte of dtbc is greater than 128
    byte pruefzifferHeader = pzBase64Decoded[0];
    if ((pruefzifferHeader & MSB_MASK) == 0) {
      return "FAIL: Prüfziffer Version 1 detected";
    } else {
      log.info("Prüfziffer Version 2 detected");
    }

    // Step 4: Check if there is an AES/GCM key for the prefix
    if (!vsdmKey.containsKey(pruefzifferHeader)) {
      return "FAIL: No decryption key for the prefix";
    }

    // Step 5: Extract IV and ciphertext
    byte[] iv = Arrays.copyOfRange(pzBase64Decoded, 1, 13);
    if (iv.length != IV_LENGTH) {
      return "FAIL: IV has invalid length";
    }

    byte[] ciphertext = Arrays.copyOfRange(pzBase64Decoded, 13, pzBase64Decoded.length);
    if (ciphertext.length != CIPHERTEXT_LENGTH) {
      return "FAIL: Ciphertext has invalid length";
    }

    // Decrypt and get plaintext
    try {
      byte[] plaintext = decryptData(pruefzifferHeader, iv, ciphertext);
      // Step 6: Validate plaintext
      return validatePlaintext(kvnr, hcv, plaintext);
    } catch (Exception e) {
      return "FAIL: Decryption error";
    }
  }

  public String validatePlaintext(String kvnr, byte[] hcv, byte[] plaintext) {
    byte[] iFeld1 = Arrays.copyOfRange(plaintext, 0, 5);
    byte[] iat8 = Arrays.copyOfRange(plaintext, 5, 8);
    byte[] plaintextKvnr = Arrays.copyOfRange(plaintext, 8, plaintext.length);

    // Step 6: Check eGK
    if ((iFeld1[0] & MSB_MASK) == MSB_MASK) {
      return "FAIL: eGK blocked";
    }

    // Step 7: Check iat
    int iat8Int = ((iat8[0] & 0xFF) << 16) | ((iat8[1] & 0xFF) << 8) | (iat8[2] & 0xFF);
    long iat = (iat8Int << 3) + IAT_TIME_OFFSET;
    long now = Instant.now().getEpochSecond();

    if (!(iat - 30 < now && now < iat + 20 * 60 + 15)) {
      return "FAIL: Prüfziffer is temporally invalid, " + (now - iat);
    }

    // Step 8: Check hcv
    if (this.enforceHcvCheck && !Arrays.equals(hcv, iFeld1)) {
      return "FAIL: HCV check failed, provided HCV does not match expected value";
    }

    // Step 9: Check KVNR
    if (plaintextKvnr.length != KVNR_LENGTH) {
      throw new IllegalArgumentException("KVNR must be 10 bytes long");
    }
    if (!Arrays.equals(plaintextKvnr, kvnr.getBytes())) {
      return "FAIL: Prüfziffer for wrong KVNR (attack?)";
    }

    return "SUCCESS";
  }

  byte[] decryptData(byte pruefzifferHeader, byte[] iv, byte[] ciphertext) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      GCMParameterSpec spec = new GCMParameterSpec(128, iv);
      cipher.init(
          Cipher.DECRYPT_MODE, new SecretKeySpec(vsdmKey.get(pruefzifferHeader), "AES"), spec);
      return cipher.doFinal(ciphertext);
    } catch (Exception e) {
      log.error("Decryption failed", e);
      throw new IllegalArgumentException("Decryption failed", e);
    }
  }
}
