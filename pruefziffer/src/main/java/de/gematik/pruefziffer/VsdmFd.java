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

import static de.gematik.pruefziffer.Utils.bytesToHex;
import static de.gematik.pruefziffer.Utils.concatenate;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class VsdmFd {
  private static final Charset ISO_8859_15 = Charset.forName("ISO-8859-15");
  private static final int COMMON_SECRET_MIN_LENGTH = 32;
  private static final int MAX_KEY_VERSION = 3;
  private static final int KVNR_LENGTH = 10;
  private static final int VB_LENGTH = 8;
  private static final int PLAINTEXT_LENGTH = 18;
  private static final int CIPHERTEXT_LENGTH = 34;

  private final byte[] encKey;
  private final byte[] pzv2Prefix;
  private final Map<String, Map<String, String>> vsdmDb;

  public VsdmFd(String betreiberkennung, byte[] commonSecret, int keyVersion) {
    validateInputs(betreiberkennung, commonSecret, keyVersion);
    this.encKey = Utils.deriveAesKeyFromSecret(commonSecret);
    this.pzv2Prefix = Utils.calculatePZv2Prefix(betreiberkennung, keyVersion);
    this.vsdmDb = Utils.loadDb();
    logInitialization(betreiberkennung, commonSecret, keyVersion);
  }

  public Map<String, String> readVSD(String iccsn) {
    if (!vsdmDb.containsKey(iccsn)) {
      throw new IllegalArgumentException("ICCSN not found in database");
    }
    return vsdmDb.get(iccsn);
  }

  public void validateInputs(String betreiberkennung, byte[] commonSecret, int keyVersion) {
    if (commonSecret.length < COMMON_SECRET_MIN_LENGTH) {
      throw new IllegalArgumentException("Invalid commonSecret length");
    }
    if (betreiberkennung.length() != 1)
      throw new IllegalArgumentException("Invalid betreiberkennung length");

    if (keyVersion < 0 || keyVersion >= MAX_KEY_VERSION)
      throw new IllegalArgumentException("Invalid keyVersion");
  }

  private void logInitialization(String betreiberkennung, byte[] commonSecret, int keyVersion) {
    log.info(
        "VSDM-FD initialized with betreiberkennung={}, keyVersion={}",
        betreiberkennung,
        keyVersion);
    log.info("Common secret: {}", bytesToHex(commonSecret));
    log.info("Secret AES/GCM key: {}", bytesToHex(this.encKey));
    log.info("PZ2 prefix is (hexdump): {}", bytesToHex(this.pzv2Prefix));
    log.info("iatTimeOffset={}", Utils.IAT_TIME_OFFSET);
  }

  // A_27278 - VSDM-FD: Struktur einer Prüfziffer der Version 2
  @SneakyThrows
  public String genPruefziffer(String iccsn) {
    byte[] rIat8Bytes = Utils.calculateRIat8Value();

    Map<String, String> vsdmData = this.vsdmDb.get(iccsn);
    if (vsdmData == null) throw new IllegalArgumentException("ICCSN not found in database");

    String kvnr = vsdmData.get("KVNR");
    if (kvnr.getBytes(ISO_8859_15).length != KVNR_LENGTH) {
      throw new IllegalArgumentException("KVNR must be 10 characters long");
    }
    String vb = vsdmData.get("VB");
    String sas = vsdmData.get("Strasse");
    boolean revoked = Boolean.parseBoolean(vsdmData.get("revoked"));

    byte[] hcv = generateHcv(vb, sas);
    log.info("H_40_0 = (hexdump) " + DatatypeConverter.printHexBinary(hcv));

    byte[] iFeld1 = revoked ? Utils.setRevokedFlag(hcv) : hcv;
    log.info("iFeld1 = (hexdump) " + bytesToHex(iFeld1));
    log.info("r_iat_8 = (hexdump) " + bytesToHex(rIat8Bytes));

    // Create internal data structure (plaintext), see table A_27278
    byte[] plaintext = concatenate(iFeld1, rIat8Bytes, kvnr.getBytes(ISO_8859_15));
    if (plaintext.length != PLAINTEXT_LENGTH) {
      throw new IllegalArgumentException("Plaintext length must be 18 bytes");
    }

    byte[] iv = Utils.generateRandomIV();
    log.info("IV: " + bytesToHex(iv));

    byte[] ciphertext = encryptData(iv, plaintext);
    byte[] pzBase64Encoded = concatenate(this.pzv2Prefix, iv, ciphertext);
    if (pzBase64Encoded.length != 47) {
      throw new IllegalArgumentException("Base64-encoded Prüfziffer length must be 47 bytes");
    }

    String pruefziffer = Base64.getEncoder().encodeToString(pzBase64Encoded);
    log.info("Prüfziffer V2: " + pruefziffer);
    return pruefziffer;
  }

  private byte[] encryptData(byte[] iv, byte[] plaintext) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
    SecretKeySpec keySpec = new SecretKeySpec(this.encKey, "AES");
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

    byte[] ciphertext = cipher.doFinal(plaintext);
    log.info("Ciphertext: " + bytesToHex(ciphertext));
    if (ciphertext.length != CIPHERTEXT_LENGTH) {
      throw new IllegalArgumentException("Ciphertext length must be 34 bytes");
    }
    return ciphertext;
  }

  @SneakyThrows
  // A_27352: VSDM-Prüfziffer Version 2: Erzeugung von hcv
  public byte[] generateHcv(String vb, String sas) {
    // Step 1: VB contains no spaces,  ISO-8859-15 (Latin-9) encoding
    if (vb.contains(" ")) {
      throw new IllegalArgumentException("VB must not contain spaces");
    }
    byte[] vbBytes = vb.getBytes(ISO_8859_15);
    if (vbBytes.length != VB_LENGTH) {
      throw new IllegalArgumentException("VB must be 8 bytes when encoded in ISO-8859-15");
    }
    // Step 2: SAS - no leading and trailing spaces, ISO-8859-15 (Latin-9) encoding
    sas = sas.trim();
    byte[] sasBytes = sas.getBytes(ISO_8859_15);

    // Step 3: Concatenate VB and Strasse
    byte[] concatenated = Utils.concatenate(vbBytes, sasBytes);

    // Step 4: Compute SHA-256 hash
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    byte[] hash = sha256.digest(concatenated);
    if (hash.length != 32) {
      throw new IllegalArgumentException("Concatenated length must be 32 bytes");
    }
    log.info("Data-to-hashed(hexdump): " + Utils.bytesToHex(concatenated));

    // Step 5: Extract the first 5 bytes (40 bits)
    byte[] h40 = Arrays.copyOfRange(hash, 0, 5);
    if (h40.length != 5) {
      throw new IllegalArgumentException("h40 length must be 5 bytes");
    }

    // Step 6: Set the MSB of the first byte to 0
    // h_40_0 now contains the modified first byte and the rest of the bytes from h_40
    h40[0] = (byte) (h40[0] & 127);
    log.info("Generated hcv by VSDM-FD: " + Utils.bytesToHex(h40));
    return h40;
  }
}
