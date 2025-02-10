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

import java.util.Arrays;

public record VsdmFdData(String betreiberkennung, int version, byte[] commonSecret) {

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    VsdmFdData that = (VsdmFdData) o;
    return version == that.version
        && betreiberkennung.equals(that.betreiberkennung)
        && Arrays.equals(commonSecret, that.commonSecret);
  }

  @Override
  public int hashCode() {
    int result = betreiberkennung.hashCode();
    result = 31 * result + Integer.hashCode(version);
    result = 31 * result + Arrays.hashCode(commonSecret);
    return result;
  }

  @Override
  public String toString() {
    return "VsdmFdData{"
        + "betreiberkennung='"
        + betreiberkennung
        + '\''
        + ", version="
        + version
        + ", commonSecret="
        + Arrays.toString(commonSecret)
        + '}';
  }
}
