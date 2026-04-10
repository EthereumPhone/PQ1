#
# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

"""License text"""

import ctypes
import logging
from . import sss_api as apis


log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(message)s')

class GetMemory:
    """
    Get available Free Memory
    """
    memory_type_names = {
       apis.kSE05x_MemoryType_PERSISTENT: "Persistent Memory",
       apis.kSE05x_MemoryType_TRANSIENT_RESET: "Transient Memory (Clean on Reset)",
       apis.kSE05x_MemoryType_TRANSIENT_DESELECT: "Transient Memory (Clear on Deselect)"
   }

    def __init__(self, session_obj):
        """
        Constructor
        :param session_obj: Instance of session
        """
        self._session = session_obj

    def do_get_available_memory(self,memory_type):  # pylint: disable=too-many-locals, too-few-public-methods
        """
        Get Available memory
        :return: Status
        """
        available_memory = ctypes.c_uint32(0)
        status = apis.Se05x_API_GetFreeMemory(ctypes.byref(self._session.session_ctx.s_ctx), memory_type, ctypes.pointer(available_memory))
        if status != apis.kSE05x_SW12_NO_ERROR:
            log.error("Se05x_API_GetFreeMemory Failed")
        else:
            memory_type_name = self.memory_type_names.get(memory_type, 'UNKNOWN')
            log.info(f"{memory_type_name:<40}: {available_memory.value}")
        return status
