#
# Copyright 2018,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#

import os
from sss_mbedtls_config_common import *

HEADER_FILE = os.path.abspath(os.path.dirname(__file__)) + os.sep + ".." + os.sep + "port" + os.sep + "ksdk" + os.sep + "sss_ksdk_mbedtls_config.h"

# [Macro to define, dependencies...]
DEFINE_MACROS = [
    ["MBEDTLS_ECP_DP_SECP192R1_ENABLED",
        # Doc
        None
    ],
    ["MBEDTLS_ECP_DP_SECP224R1_ENABLED",
        # Doc
        None
    ],
    ["MBEDTLS_ECP_DP_SECP384R1_ENABLED",
        # Doc
        None
    ],
    ["MBEDTLS_ECP_DP_SECP192K1_ENABLED",
        # Doc
        None
    ],
    ["MBEDTLS_ECP_DP_SECP224K1_ENABLED",
        # Doc
        None
    ],
    ["MBEDTLS_ECP_DP_SECP256K1_ENABLED",
        # Doc
        None
    ],
    ["MBEDTLS_ECP_DP_BP256R1_ENABLED",
        # Doc
        None
    ],
    ["MBEDTLS_ECP_DP_BP384R1_ENABLED",
        # Doc
        None
    ],
    ["MBEDTLS_ECP_DP_BP512R1_ENABLED",
        # Doc
        None
    ],
    ["MBEDTLS_ECP_DP_CURVE25519_ENABLED",
        # Doc
        "/* Montgomery curves (supporting ECP) */"
    ],
    ["MBEDTLS_ECP_DP_CURVE448_ENABLED",
        # Doc
        "/* Montgomery curves (supporting ECP) */"
    ],
    ["MBEDTLS_CMAC_C",
        # Doc
        None
    ],
    # L1
    ["MBEDTLS_ECP_DP_SECP521R1_ENABLED",
        # dependencies
        "ndef MBEDTLS_FREESCALE_LTC_PKHA",
        # Doc
        None
    ],
    ["MBEDTLS_ECP_ALT",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        # Doc
        None
    ],
    ["MBEDTLS_ECDH_ALT",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        # Doc
        None
    ],
    ["MBEDTLS_ECDH_GEN_PUBLIC_ALT",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        # Doc
        None
    ],
    ["MBEDTLS_ECDH_COMPUTE_SHARED_ALT",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        # Doc
        None
    ],
    ["MBEDTLS_CTR_DRBG_C",
        # dependencies
        " defined(IMX_RT)",
        # Doc
        "/* We need this for mbedTLS sw crypto counterpart */"
    ],
    ["MBEDTLS_CTR_DRBG_C",
        # dependencies
        " defined(LPC_55x)",
        # Doc
        "/* We need this for mbedTLS sw crypto counterpart */"
    ],
    # L2
    ["MBEDTLS_RSA_ALT",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " SSS_HAVE_RSA",
        # Doc
        None
    ],
	["MBEDTLS_ECDH_LEGACY_CONTEXT",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        # Doc
        None
    ],
]

# [Macro to undefine, dependencies...]
UNDEFINE_MACROS = [
    ["MBEDTLS_HKDF_C",
        # Doc
        None
    ],
    ["MBEDTLS_SELF_TEST",
        # Doc
        None
    ],
    ["MBEDTLS_PSA_CRYPTO_C",
        # Doc
        None
    ],
    ["MBEDTLS_PSA_CRYPTO_STORAGE_C",
        # Doc
        None
    ],
    ["MBEDTLS_PSA_ITS_FILE_C",
        # Doc
        None
    ],
    # L1
    ["MBEDTLS_AES_ALT",
        # dependencies
        " defined(CPU_QN9090)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_SETKEY_ENC_ALT",
        # dependencies
        " defined(CPU_QN9090)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_SETKEY_DEC_ALT",
        # dependencies
        " defined(CPU_QN9090)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_ENCRYPT_ALT",
        # dependencies
        " defined(CPU_QN9090)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_DECRYPT_ALT",
        # dependencies
        " defined(CPU_QN9090)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_CRYPT_CBC_ALT",
        # dependencies
        " defined(CPU_QN9090)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_CRYPT_CFB_ALT",
        # dependencies
        " defined(CPU_QN9090)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_CRYPT_CTR_ALT",
        # dependencies
        " defined(CPU_QN9090)",
        # Doc
        None
    ],
    ["MBEDTLS_FREESCALE_LPC_AES",
        # dependencies
        " defined(CPU_QN9090)",
        # Doc
        None
    ],
    ["MBEDTLS_MCUX_CASPER_ECC",
        # dependencies
        " defined(LPC_55x)",
        # Doc
        None
    ],
    ["MBEDTLS_ECP_MUL_COMB_ALT",
        # dependencies
        " defined(LPC_55x)",
        # Doc
        None
    ],
    ["MBEDTLS_ECP_MULADD_ALT",
        # dependencies
        " defined(LPC_55x)",
        # Doc
        None
    ],
    # L2
    ["MBEDTLS_AES_SETKEY_ENC_ALT",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(IMX_RT)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_SETKEY_DEC_ALT",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(IMX_RT)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_ENCRYPT_ALT",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(IMX_RT)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_DECRYPT_ALT",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(IMX_RT)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_ALT_NO_192",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(IMX_RT)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_CRYPT_CBC_ALT",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(IMX_RT)",
        # Doc
        None
    ],
    ["MBEDTLS_FREESCALE_DCP_AES",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(IMX_RT)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_ALT",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(IMX_RT)",
        # Doc
        "/* If We use ALT from the EVKB, anything that is related to\n\
 * AES256 would get skipped and because of this TLS Handshake\n\
 * would not pass\n\
 *\n\
 * Disabling this altogether. May be there's a way to use AES256\n\
 * on EVKB with mbedTLS but need to Check.\n\
 */"
    ],
    ["MBEDTLS_AES_ALT_NO_256",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(IMX_RT)",
        # Doc
        None
    ],
    ["MBEDTLS_FREESCALE_LTC_AES",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(CPU_MIMXRT1176DVMAA_cm7)",
        # Doc
        None
    ],
    ["MBEDTLS_FREESCALE_MMCAU_AES",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(CPU_MIMXRT1176DVMAA_cm7)",
        # Doc
        None
    ],
    ["MBEDTLS_FREESCALE_LPC_AES",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(CPU_MIMXRT1176DVMAA_cm7)",
        # Doc
        None
    ],
    ["MBEDTLS_FREESCALE_CAU3_AES",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(CPU_MIMXRT1176DVMAA_cm7)",
        # Doc
        None
    ],
    ["MBEDTLS_FREESCALE_CAAM_AES",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(CPU_MIMXRT1176DVMAA_cm7)",
        # Doc
        None
    ],
    ["MBEDTLS_FREESCALE_DCP_AES",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(CPU_MIMXRT1176DVMAA_cm7)",
        # Doc
        None
    ],
    ["MBEDTLS_CCM_CRYPT_ALT",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(CPU_MIMXRT1176DVMAA_cm7)",
        # Doc
        None
    ],
    ["MBEDTLS_GCM_CRYPT_ALT",
        # dependencies
        " SSS_HAVE_MBEDTLS_ALT",
        " defined(CPU_MIMXRT1176DVMAA_cm7)",
        # Doc
        None
    ],
    ["MBEDTLS_ECP_DP_CURVE25519_ENABLED",
        # dependencies
        " defined(CPU_MIMXRT1176DVMAA_cm7)",
        # Doc
        None
    ],
    ["MBEDTLS_ECP_DP_CURVE448_ENABLED",
        # dependencies
        " defined(CPU_MIMXRT1176DVMAA_cm7)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_SETKEY_ENC_ALT",
        # dependencies
        " defined(USE_RTOS) && (USE_RTOS == 1)",
        " defined(CPU_MIMXRT1062DVL6A) || defined(CPU_MIMXRT1062DVL6B)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_SETKEY_DEC_ALT",
        # dependencies
        " defined(USE_RTOS) && (USE_RTOS == 1)",
        " defined(CPU_MIMXRT1062DVL6A) || defined(CPU_MIMXRT1062DVL6B)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_ENCRYPT_ALT",
        # dependencies
        " defined(USE_RTOS) && (USE_RTOS == 1)",
        " defined(CPU_MIMXRT1062DVL6A) || defined(CPU_MIMXRT1062DVL6B)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_DECRYPT_ALT",
        # dependencies
        " defined(USE_RTOS) && (USE_RTOS == 1)",
        " defined(CPU_MIMXRT1062DVL6A) || defined(CPU_MIMXRT1062DVL6B)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_ALT_NO_192",
        # dependencies
        " defined(USE_RTOS) && (USE_RTOS == 1)",
        " defined(CPU_MIMXRT1062DVL6A) || defined(CPU_MIMXRT1062DVL6B)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_CRYPT_CBC_ALT",
        # dependencies
        " defined(USE_RTOS) && (USE_RTOS == 1)",
        " defined(CPU_MIMXRT1062DVL6A) || defined(CPU_MIMXRT1062DVL6B)",
        # Doc
        None
    ],
    ["MBEDTLS_FREESCALE_DCP_AES",
        # dependencies
        " defined(USE_RTOS) && (USE_RTOS == 1)",
        " defined(CPU_MIMXRT1062DVL6A) || defined(CPU_MIMXRT1062DVL6B)",
        # Doc
        None
    ],
    ["MBEDTLS_AES_ALT",
        # dependencies
        " defined(USE_RTOS) && (USE_RTOS == 1)",
        " defined(CPU_MIMXRT1062DVL6A) || defined(CPU_MIMXRT1062DVL6B)",
        # Doc
        "/* If We use ALT from the EVKB, anything that is related to\n\
 * AES256 would get skipped and because of this TLS Handshake\n\
 * would not pass\n\
 *\n\
 * Disabling this altogether. May be there's a way to use AES256\n\
 * on EVKB with mbedTLS but need to Check.\n\
 */"
    ],
    ["MBEDTLS_AES_ALT_NO_256",
        # dependencies
        " defined(USE_RTOS) && (USE_RTOS == 1)",
        " defined(CPU_MIMXRT1062DVL6A) || defined(CPU_MIMXRT1062DVL6B)",
        # Doc
        None
    ],
]

PLATFORM_MEMORY_DEFINE = [
    ["MBEDTLS_PLATFORM_MEMORY",
        # Doc
        None
    ],
]
PLATFORM_MEMORY_UNDEFINE = [
    ["MBEDTLS_PLATFORM_STD_CALLOC",
        # Doc
        None
    ],
    ["MBEDTLS_PLATFORM_STD_FREE",
        # Doc
        None
    ],
    ["MBEDTLS_PLATFORM_CALLOC_MACRO",
        # Doc
        None
    ],
    ["MBEDTLS_PLATFORM_FREE_MACRO",
        # Doc
        None
    ],
]

class KSDKDefineMacros(DefineMacros):
    def __init__(self, o_file):
        super(KSDKDefineMacros, self).__init__()
        self.o_file = o_file
        self._method = "DEFINE"

    def write_platform_memory(self):
        self.write(PLATFORM_MEMORY_DEFINE, "DEFINE")
        self.write(PLATFORM_MEMORY_UNDEFINE, "UNDEFINE")
        self.o_file.write("\n\n#define MBEDTLS_PLATFORM_CALLOC_MACRO SSS_CALLOC")
        self.o_file.write("\n#define MBEDTLS_PLATFORM_FREE_MACRO SSS_FREE\n")

def main():
    o = open(HEADER_FILE, "w")
    macros = KSDKDefineMacros(o)
    o.write(COPYRIGHT)
    o.write(C_HEADER_START)
    o.write("/* Generated by %s */\n\n" %(os.path.basename(__file__)))
    macros.write(DEFINE_MACROS, "DEFINE")
    macros.write(UNDEFINE_MACROS, "UNDEFINE")

    # Write Platform memory macros
    o.write("#include <fsl_sss_types.h>\n\n")
    macros.write_platform_memory()
    o.write(C_HEADER_END)
    o.close()

if __name__ == "__main__":
    main()

