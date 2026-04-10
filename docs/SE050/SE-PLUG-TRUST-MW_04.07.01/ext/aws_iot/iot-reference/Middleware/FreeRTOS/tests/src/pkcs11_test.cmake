set( PKCS11_TEST_SOURCES "${CMAKE_CURRENT_LIST_DIR}/pkcs11/core_pkcs11_test.c"
                         "${CMAKE_CURRENT_LIST_DIR}/pkcs11/dev_mode_key_provisioning/dev_mode_key_provisioning.c" )

set( PKCS11_TEST_INCLUDE_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/pkcs11"
    "${CMAKE_CURRENT_LIST_DIR}/pkcs11/dev_mode_key_provisioning"
    "${CMAKE_CURRENT_LIST_DIR}/common" )
