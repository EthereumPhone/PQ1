# Copyright 2024 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

from enum import Enum

class ProductHardwareFamilyType(Enum):
    """
    All product hardware family types.
    """

    SE05    = 1
    A500    = 2
    RW6     = 3
    IMX8    = 4
    IMX9    = 5
    IMXRT   = 6
    KW      = 7
