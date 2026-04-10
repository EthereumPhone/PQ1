#
# Copyright 2018,2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
MACRO(CREATE_BINARY PROJECT_NAME)
    IF(
        "${CMAKE_SYSTEM_NAME}"
        STREQUAL
        "WindowsStore"
    )
        SET_PROPERTY(TARGET ${PROJECT_NAME} PROPERTY VS_WINRT_COMPONENT TRUE)
    ENDIF()

    IF(SSS_HAVE_HOST_WIN10IOT)
        SET_TARGET_PROPERTIES(
            ${PROJECT_NAME} PROPERTIES LINK_FLAGS_RELEASE "/defaultlib:vccorlib.lib /defaultlib:msvcrt.lib"
        )
        SET_TARGET_PROPERTIES(
            ${PROJECT_NAME} PROPERTIES LINK_FLAGS_DEBUG "/defaultlib:vccorlibd.lib /defaultlib:msvcrtd.lib"
        )
    ENDIF()
ENDMACRO()

MACRO(
    COPY_TO_SOURCEDIR
    PROJECT_NAME
    TARGET_DIRNAME
    TARGET_SUFFIX
)
    ADD_CUSTOM_COMMAND(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}>
                ${SIMW_TOP_DIR}/${TARGET_DIRNAME}/${TARGET_SUFFIX}-$<TARGET_FILE_NAME:${PROJECT_NAME}>
        COMMENT "Copy ${PROJECT_NAME} to ${SIMW_TOP_DIR}/${TARGET_DIRNAME}"
    )
ENDMACRO()

#SET(CMAKE_EXECUTABLE_SUFFIX ".exe")

MACRO(
    COPY_TO_SOURCEDIR_RENAME
    PROJECT_NAME
    PROJECT_RENAMED
    TARGET_DIRNAME
    TARGET_SUFFIX
)
    ADD_CUSTOM_COMMAND(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}>
                ${CMAKE_SOURCE_DIR}/${TARGET_DIRNAME}/${TARGET_SUFFIX}-${PROJECT_RENAMED}${CMAKE_EXECUTABLE_SUFFIX}
        COMMENT "Copy ${PROJECT_NAME} to ${CMAKE_SOURCE_DIR}/${TARGET_DIRNAME}"
    )
ENDMACRO()

IF(CMAKE_COMPILER_IS_GNUCC)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-result ")

    IF(NXPInternal)
        ADD_COMPILE_OPTIONS(-Wextra)
        ADD_COMPILE_OPTIONS(-Werror)
        ADD_COMPILE_OPTIONS(-Wno-error=missing-field-initializers)
        ADD_COMPILE_OPTIONS(-Wno-missing-field-initializers)
        ADD_COMPILE_OPTIONS(-Wno-error=extra)
    ENDIF()

    MACRO(SIMW_DISABLE_EXTRA_WARNINGS PROJECT_NAME)
        TARGET_COMPILE_OPTIONS(
            ${PROJECT_NAME}
            PRIVATE -Wno-error=missing-field-initializers
            PRIVATE -Wno-missing-field-initializers
            PRIVATE -Wno-error=sign-compare
            PRIVATE -Wno-sign-compare
            PRIVATE -Wno-error=unused-parameter
            PRIVATE -Wno-unused-parameter
            PRIVATE -Wno-error=implicit-fallthrough
            PRIVATE -Wno-implicit-fallthrough
            PRIVATE -Wno-error=missing-field-initializers
            PRIVATE -Wno-missing-field-initializers
        )
    ENDMACRO()

ENDIF()

IF(
    CMAKE_CXX_COMPILER_ID
    MATCHES
    "Clang"
)
    IF(NXPInternal)
        ADD_COMPILE_OPTIONS(-Werror -Wall)
        ADD_COMPILE_OPTIONS(-Wextra)
        ADD_COMPILE_OPTIONS(-Wno-unused-parameter)
        ADD_COMPILE_OPTIONS(-Wno-unknown-pragmas)
        ADD_COMPILE_OPTIONS(-Wno-missing-field-initializers)
        ADD_COMPILE_OPTIONS(-Wno-missing-braces)
    ENDIF()

    MACRO(SIMW_DISABLE_EXTRA_WARNINGS PROJECT_NAME)

    ENDMACRO()

ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    IF(NXPInternal)
        ADD_COMPILE_OPTIONS(/W4)
        ADD_COMPILE_OPTIONS(/wd4100) # unreferenced formal parameter
        ADD_COMPILE_OPTIONS(/wd4244) # conversion from 'int' to 'uint8_t', possible loss of data
        ADD_COMPILE_OPTIONS(/wd4244) # conversion from 'int' to 'uint8_t', possible loss of data
        ADD_COMPILE_OPTIONS(/wd4210) # nonstandard extension used: function given file scope
        ADD_COMPILE_OPTIONS(/wd4204) # nonstandard extension used: non-constant aggregate initializer
        ADD_COMPILE_OPTIONS(/wd4221) # cannot be initialized using address of automatic variable ''
        ADD_COMPILE_OPTIONS(/wd4206) # nonstandard extension used: translation unit is empty
        ADD_COMPILE_OPTIONS(/wd4214) # nonstandard extension used: bit field types other than int
        ADD_COMPILE_OPTIONS(/wd4201) # nonstandard extension used: nameless struct/union
        ADD_COMPILE_OPTIONS(/WX)
    ENDIF()

    MACRO(SIMW_DISABLE_EXTRA_WARNINGS PROJECT_NAME)

    ENDMACRO()

ENDIF()

ADD_DEFINITIONS(-DFTR_FILE_SYSTEM)

IF(SSS_HAVE_HOST_PCLINUX OR SSS_HAVE_HOST_IMXLINUX)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
ENDIF()

IF(SSS_HAVE_HOST_PCLINUX32)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
    LINK_DIRECTORIES("/usr/lib/i386-linux-gnu/")
ENDIF()

IF(SSS_HAVE_HOST_PCLINUX64)
    INCLUDE_DIRECTORIES(/usr/include/x86_64-linux-gnu)
ENDIF()

IF(SSS_HAVE_HOST_PCWINDOWS)
    ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS)
    IF(
        "${CMAKE_CXX_COMPILER_ID}"
        MATCHES
        "MSVC"
    )
        IF(SSS_HAVE_OPENSSL_1_1_1)
            LINK_DIRECTORIES(${SIMW_TOP_DIR}/ext/openssl/lib)
        ENDIF()
        IF(SSS_HAVE_OpenSSL_1_0_2)
            LINK_DIRECTORIES(${SIMW_TOP_DIR}/ext/openssl-102/lib_vs2015)
        ENDIF()
        IF(SSS_HAVE_OPENSSL_3_0)
            LINK_DIRECTORIES(${SIMW_TOP_DIR}/ext/openssl-30/lib)
        ENDIF()
    ELSE()
        # MINGW
        IF(SSS_HAVE_OpenSSL_1_1_1)
            LINK_DIRECTORIES(${SIMW_TOP_DIR}/ext/openssl/lib_mingw)
        ENDIF()
        IF(SSS_HAVE_OpenSSL_1_0_2)
            MESSAGE(FATAL "SSS_HAVE_OpenSSL_1_0_2 is only available for MSVC")
        ENDIF()
        IF(SSS_HAVE_OPENSSL_3_0)
            MESSAGE(FATAL "SSS_HAVE_OpenSSL_3_0 is only available for MSVC")
        ENDIF()
    ENDIF()

    IF(SSS_HAVE_RTOS_FREERTOS)
        LINK_DIRECTORIES(${SIMW_TOP_DIR}/ext/amazon-freertos/libraries/3rdparty/win_pcap)
    ENDIF()

ENDIF()

IF(SSS_HAVE_HOST_WIN10IOT)
    ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS)
    LINK_DIRECTORIES(${SIMW_TOP_DIR}/ext/openssl-102/Win10IoT/lib)
ENDIF()

IF(SSS_HAVE_HOST_IMXLINUX OR SSS_HAVE_HOST_RASPBIAN)
    SET(CMAKE_INSTALL_LIBDIR lib)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
ENDIF()

IF(SSS_HAVE_HOST_ANDROID)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -fPIE -fPIC")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -fPIC")
    SET(CMAKE_LD_FLAGS "${CMAKE_LD_FLAGS} -pie -lpthread")
ENDIF()
