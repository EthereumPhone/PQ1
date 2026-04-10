# Copyright 2024 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

from enum import Enum

class ProvisioningState(Enum):
    """
    All provisioning states.
    """
    GENERATION_TRIGGERED      = 1
    GENERATION_COMPLETED      = 2
    GENERATION_FAILED         = 3
    PROVISIONING_COMPLETED    = 4
    PROVISIONING_FAILED       = 5
    GENERATION_ON_CONNECTION  = 6