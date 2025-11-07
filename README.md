# epa-poc-collection

#### This repository is a collection of Proof of Concepts (POCs) and is provided without any further support. It is only a sample implementation.

However, you can still submit an issue or pull request for any bugs or vulnerabilities found

## pruefziffer

In the pruefziffer module, the creation of a Prüfziffer by a VSDM-FD, the creation of the hcv(Hash Check Value) through the Primärsystem, and the verification
of the hcv and
Prüfziffer in an AS or E-Rezept-FD are included as sample implementations.

The POC was originally implemented in Python and has been translated to Java, demonstrating an example implementation for C_12143.

See more details and example implementation of the Python POC:
[https://bitbucket.org/andreas_hallof/pop-egk-vsdm/src/master/encrypted_vsdmplus/](https://bitbucket.org/andreas_hallof/pop-egk-vsdm/src/master/encrypted_vsdmplus/)

#### VsdmFd.java

This file contains the creation of a hcv and Prüfziffer by a VSDM-FD.

#### Aktensystem.java

This file contains the verification of a Prüfziffer by Aktensystem or E-Rezept-FD.

#### IntegrationTest.java

This file contains parameterized and individual test cases for generating and verifying hcv and Prüfziffern based on test data.
The test data is derived from the Python POC and the table specified in Change A_27352 VSDM-Prüfziffer Version 2: Erzeugung von hcv.

## License

Copyright 2025 gematik GmbH

Apache License, Version 2.0

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under the License.

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
    2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
    3. The software is the result of research and development activities, therefore not necessarily quality assured and without the character of a liable product. For this reason, gematik does not provide any support or other user assistance (unless otherwise stated in individual cases and without justification of a legal obligation). Furthermore, there is no claim to further development and adaptation of the results to a more current state of the art.
3. Gematik may remove published results temporarily or permanently from the place of publication at any time without prior notice or justification.
4. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.

