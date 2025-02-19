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
