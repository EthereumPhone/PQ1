# Add set(CONFIG_USE_middleware_mbedtls_port_els_pkc true) in config.cmake to use this component

include_guard(GLOBAL)
message("${CMAKE_CURRENT_LIST_FILE} component is included.")

if((CONFIG_DEVICE_ID STREQUAL MCXN947) AND CONFIG_USE_middleware_mbedtls_port_els AND CONFIG_USE_component_els_pkc AND CONFIG_USE_middleware_mbedtls_els_pkc_config)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/port/pkc/ecc_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/port/pkc/ecdh_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/port/pkc/ecdsa_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/port/pkc/rsa_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/port/pkc/els_pkc_mbedtls.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/port/pkc
)

if(CONFIG_USE_COMPONENT_CONFIGURATION)
  message("===>Import configuration from ${CMAKE_CURRENT_LIST_FILE}")

  target_compile_definitions(${MCUX_SDK_PROJECT_NAME} PUBLIC
    -DMBEDTLS_MCUX_ELS_PKC_API
    -DMBEDTLS_MCUX_USE_PKC
    -DMBEDTLS_CONFIG_FILE="els_pkc_mbedtls_config.h"
  )

endif()

else()

message(SEND_ERROR "middleware_mbedtls_port_els_pkc dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()
