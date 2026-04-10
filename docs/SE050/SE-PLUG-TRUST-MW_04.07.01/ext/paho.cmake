#Include Paho for MQTT demo examples

IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)

    IF(
        "${CMAKE_CXX_COMPILER_ID}"
        MATCHES
        "MSVC"
    )
        add_compile_options(
            /wd4310 # cast truncates constant value
            /wd4389 # '==': signed/unsigned mismatch
            /wd4132 # const object should be initialized
            /wd4127 # conditional expression is constant
            /wd4701 # potentially uninitialized local variable
            /wd4477 # 'printf' : format string '%d'
            /wd4706 #  assignment within conditional expression
            /wd4024 # 'function' : different types for formal and actual parameter 'number'
            /wd4189 # 'identifier' : local variable is initialized but not referenced
            /wd4456 # 'declaration of 'identifier' hides previous local declaration
            /wd4702 # unreachable code
            /wd4018
            /wd4245
            /wd4101
        )
    ENDIF()


    IF(
        "${CMAKE_CXX_COMPILER_ID}"
        STREQUAL
        "GNU"
    )
        add_compile_options(
            -Wno-unused-function
            -Wno-error=pointer-sign
            -Wno-error=format
            -Wno-format
            -Wno-error=format-security
            -Wno-format-security
            -Wno-error=sign-compare
            -Wno-sign-compare
            -Wno-error=missing-field-initializers
            -Wno-missing-field-initializers
            -Wno-error=type-limits
            -Wno-type-limits
            -Wno-unused-parameter
            -Wno-switch-default
            -Wno-missing-declarations
            -Wno-undef
        )

        SET(GCC_VERSION_WITH_UNUSED_CONST 6.3.0)
        IF(
            GCC_VERSION_WITH_UNUSED_CONST
            VERSION_LESS
            CMAKE_CXX_COMPILER_VERSION
        )
            add_compile_options(
                -Wno-implicit-function-declaration
                -Wno-error=unused-const-variable
                -Wno-unused-const-variable
            )
        ENDIF()
    ENDIF()

IF(BUILD_SHARED_LIBS)
    SET(PAHO_BUILD_SHARED TRUE CACHE BOOL "Build shared library")
    SET(PAHO_BUILD_STATIC FALSE CACHE BOOL "Build static library")
ELSE()
    SET(PAHO_BUILD_SHARED FALSE CACHE BOOL "Build shared library")
    SET(PAHO_BUILD_STATIC TRUE CACHE BOOL "Build static library")
ENDIF()
    SET(PAHO_WITH_SSL TRUE CACHE BOOL "Flag that defines whether to build ssl-enabled binaries too. ")
    SET(PAHO_ENABLE_TESTING FALSE CACHE BOOL "Build tests and run")
IF(NOT SSS_HAVE_HOST_LINUX_LIKE)
    IF(SSS_HAVE_OPENSSL_1_1_1)
    SET(OPENSSL_ROOT_DIR "${SIMW_TOP_DIR}/ext/openssl" CACHE PATH "Directory containing OpenSSL libraries and includes")
        SET(CMAKE_IGNORE_PATH ${SIMW_TOP_DIR}/ext/openssl-30/lib)
    ELSE()
        SET(OPENSSL_ROOT_DIR "${SIMW_TOP_DIR}/ext/openssl-30" CACHE PATH "Directory containing OpenSSL libraries and includes")
        MESSAGE("Open ssl OPENSSL_ROOT_DIR from ext cmake: ${OPENSSL_ROOT_DIR}")
        SET(CMAKE_IGNORE_PATH ${SIMW_TOP_DIR}/ext/openssl/lib)
    ENDIF()
    SET(OPENSSL_USE_STATIC_LIBS TRUE CACHE BOOL "Use openssl static library")
    SET(OPENSSL_MSVC_STATIC_RT TRUE CACHE BOOL "to choose the MT version of the lib")
ENDIF()

   ADD_SUBDIRECTORY(paho.mqtt.c)
ENDIF()

