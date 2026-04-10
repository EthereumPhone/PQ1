#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#

import sys
import platform
SUBSYSTEM = "se05x"

# t1oi2c connection method used in iMX
if 'imx' in platform.node() or 'raspberrypi' in platform.node():
    CONNECTION_METHOD = "t1oi2c"
else:
    CONNECTION_METHOD = "vcom"



