# Copyright 2024 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

import logging
from twister_harness import DeviceAdapter
from twister_harness import Shell

logger = logging.getLogger(__name__)


def test_el2go_claimcode_encryption(dut: DeviceAdapter, shell: Shell):
    devmem_addresses_as_str = ''
    for i in range(167):
        line = shell.exec_command(f'devmem {hex(int("084A0008", 16) + int(str(i)))} 8')
        value = line[2].split()[2].replace('0x', '')
        devmem_addresses_as_str += '0' + value if len(value) == 1 else value

    with open(dut.handler_log_path) as handler_log:
        handler_log = handler_log.readlines()

    serial_addresses_as_str = ''
    for line in handler_log:
        if line.startswith('claimcode (0x'):
            serial_addresses_as_str += line.split()[2]

    logger.info('Devmem address as str %s', devmem_addresses_as_str)
    logger.info('Serial address as str: %s', serial_addresses_as_str)

    assert devmem_addresses_as_str == serial_addresses_as_str
