# Copyright 2024 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

from enum import Enum

class AlgorithmType(Enum):
    """
    All supported algorithms.
    """

    NIST_P192         = 1
    NIST_P224         = 2
    NIST_P256         = 3
    NIST_P384         = 4
    NIST_P521         = 5
    RSA_1024          = 6
    RSA_2048          = 7
    RSA_3072          = 8
    RSA_4096          = 9
    ECC_ED_25519      = 10
    ECC_MONT_DH_25519 = 11
    ECC_MONT_DH_448   = 12
    BRAINPOOLP160R1   = 13
    BRAINPOOLP192R1   = 14
    BRAINPOOLP224R1   = 15
    BRAINPOOLP256R1   = 16
    BRAINPOOLP320R1   = 17
    BRAINPOOLP384R1   = 18
    BRAINPOOLP512R1   = 19
    SECP160K1         = 20
    SECP192K1         = 21
    SECP224K1         = 22
    SECP256K1         = 23