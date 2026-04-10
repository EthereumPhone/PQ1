
import os
from itertools import permutations

CUR_DIR = os.path.abspath(os.path.dirname(__file__))
print("CUR_DIR: %s" %(CUR_DIR))
TOP_DIR = os.path.abspath(CUR_DIR + os.sep + ".." + os.sep + "..")
BIN_DIR = TOP_DIR + os.sep + "binaries" + os.sep + "Performance"

print(TOP_DIR)

HEADER_FILE_PATH = TOP_DIR + os.sep + "demos" + os.sep + "se05x_nxp" + os.sep + "mbedtls_lwip_client" + os.sep
HEADER_FILE_NAME = "ex_sss_ssl2_lwip.h"

BUILD_DIR = TOP_DIR + "_build" + os.sep + "simw-top-eclipse_arm"

if os.name == 'nt':
    copy_cmd = "copy /y"
else:
    copy_cmd = "cp"

DEFAULT_COMPILE_OPTIONS = " -DCMAKE_BUILD_TYPE=Release -DHost=frdmk64f -DSE05X_Ver=03_XX -DApplet=SE05X_C -DRTOS=FreeRTOS -DmbedTLS_ALT=SSS -DSCP=SCP03_SSS "

APP_CONFIG_SHORT_NAME = {
    "PERFORMANCE_MEASURE_WITH_SE05X": "SE", # SW(0)/SE(1)
    "ECC_KEY_TYPE": "ECC", # ECC
    "RSA_KEY_TYPE": "RSA", # RSA
    "DISABLE_EXTENDED_MASTER_SECRET": "DI", # mbedTLS(0)/SE(1)
}

app_config = {
    "PERFORMANCE_MEASURE_WITH_SE05X": 0, # SW(0)/SE(1)
    "ECC_KEY_TYPE": 0, # ECC
    "RSA_KEY_TYPE": 0, # RSA
    "DISABLE_EXTENDED_MASTER_SECRET": 0, # mbedTLS(0)/SE(1)
}

cmake_options = {
    "SE05X_Auth" : ["None", "PlatfSCP03"],
    # "optimization" : 0,
}

'''
ECC, RSA
PlatformSCP, None
mbedtls_lwip_client, mbedtls_deep_integration

SW only => -O0, -O2
'''

def create_cmake_and_header_build(app_config, target, additional_options=""):
    h_definitions = ""
    suffix = ""
    hasSe = False
    for i in list(app_config.keys()):
        h_definitions = h_definitions + "\n\
#ifndef %s\n\
#define %s %d\n\
#endif // %s\n\
" %(i,
    i, app_config[i],
    i,)
        if i == "PERFORMANCE_MEASURE_WITH_SE05X" and app_config[i] == 1:
            hasSe = True
        if app_config[i] == 1:
            suffix = suffix + "_" + APP_CONFIG_SHORT_NAME[i]
    with open(HEADER_FILE_PATH + HEADER_FILE_NAME, 'r+') as f:
        content = f.read()
        f.seek(0, 0)
        f.write(h_definitions)
        f.write(content)
    for j in list(cmake_options.keys()):
        for k in cmake_options[j]:
            if j == "SE05X_Auth" and k == "PlatfSCP03" and hasSe == False:
                continue
            file_suffix = suffix + "_" + k
            cmake_configure_cmd = "cmake %s -D%s=%s %s ." %(DEFAULT_COMPILE_OPTIONS, j, k, additional_options)
            build_cmd = "make %s -j" %(target,)
            rename_cmd = "%s " %(copy_cmd) + "bin" + os.sep + "%s.bin "%(target,) + BIN_DIR + os.sep +"%s%s.bin" %(target, file_suffix)
            os.system("cd %s && %s && %s && %s" %(BUILD_DIR, cmake_configure_cmd, build_cmd, rename_cmd, ))



# ECC
app_config = {
    "PERFORMANCE_MEASURE_WITH_SE05X": 0, # SW(0)/SE(1)
    "ECC_KEY_TYPE": 1, # ECC
    "RSA_KEY_TYPE": 0, # RSA
    "DISABLE_EXTENDED_MASTER_SECRET": 0, # mbedTLS(0)/SE(1)
}

# create_cmake_and_header_build(app_config)
# app_config["PERFORMANCE_MEASURE_WITH_SE05X"] = 1
# create_cmake_and_header_build(app_config)
# app_config["PERFORMANCE_MEASURE_WITH_SE05X"] = 1
# app_config["DISABLE_EXTENDED_MASTER_SECRET"] = 1
# create_cmake_and_header_build(app_config)

# # RSA
# app_config = {
#     "PERFORMANCE_MEASURE_WITH_SE05X": 0, # SW(0)/SE(1)
#     "ECC_KEY_TYPE": 0, # ECC
#     "RSA_KEY_TYPE": 1, # RSA
#     "DISABLE_EXTENDED_MASTER_SECRET": 0, # mbedTLS(0)/SE(1)
# }

# create_cmake_and_header_build(app_config)
# app_config["PERFORMANCE_MEASURE_WITH_SE05X"] = 1
# create_cmake_and_header_build(app_config)
# app_config["PERFORMANCE_MEASURE_WITH_SE05X"] = 1
# app_config["DISABLE_EXTENDED_MASTER_SECRET"] = 1
# create_cmake_and_header_build(app_config)

if os.name == 'nt':
    DEL_CMD = "del /s /q "
else:
    DEL_CMD = "rm -f "

os.system("cd %s && %s *.bin" %(BIN_DIR, DEL_CMD, ))

target="mbedtls_ex_sss_ssl2_client_lwip"
target_di="mbedtls_ex_sss_ssl2_client_deep_int_lwip"

for a in (0,1):
    for b in (0,1):
        for c in (0,1):
            for d in (0,1):
                app_config["PERFORMANCE_MEASURE_WITH_SE05X"] = a
                app_config["ECC_KEY_TYPE"] = b
                app_config["RSA_KEY_TYPE"] = c
                app_config["DISABLE_EXTENDED_MASTER_SECRET"] = d
                if b == c:
                    continue
                if a == 0 and d == 1:
                    pass #continue
                if d == 1:
                    create_cmake_and_header_build(app_config, target=target_di)
                else:
                    create_cmake_and_header_build(app_config, target=target)



# SW Only - Optimization -O2
# app_config["PERFORMANCE_MEASURE_WITH_SE05X"] = 0
# app_config["ECC_KEY_TYPE"] = 0
# app_config["RSA_KEY_TYPE"] = 0
# app_config["DISABLE_EXTENDED_MASTER_SECRET"] = 0


# for b in (0,1):
#     for c in (0,1):
#         if b == c:
#             continue
#         create_cmake_and_header_build(app_config, target=target,  additional_suffix="_O2")




