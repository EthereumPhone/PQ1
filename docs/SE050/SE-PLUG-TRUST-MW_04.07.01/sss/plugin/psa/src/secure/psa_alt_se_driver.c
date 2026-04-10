/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if (__ARM_FEATURE_CMSE & 1) == 0
#error "Need ARMv8-M security extensions"
#elif (__ARM_FEATURE_CMSE & 2) == 0
#error "Compile with --cmse"
#endif

#include "fsl_sss_api.h"
#include "nxLog_App.h"
#include "nxEnsure.h"
#include "psa/crypto_se_driver.h"
#include "psa_alt.h"

psa_status_t psa_alt_register_se_driver()
{
    psa_status_t status;
    psa_key_location_t location = PSA_ALT_SE05X_LOCATION;

    /* Assign SE driver structures with available PSA ALT APIs */
    psa_drv_se_t *p_driver = (psa_drv_se_t *)SSS_MALLOC(sizeof(psa_drv_se_t));
    /* doc:start:psa-assign-fp */
    psa_drv_se_key_management_t *p_key_mgmt_drv =
        (psa_drv_se_key_management_t *)SSS_MALLOC(sizeof(psa_drv_se_key_management_t));
    psa_drv_se_asymmetric_t *p_asymm_drv = (psa_drv_se_asymmetric_t *)SSS_MALLOC(sizeof(psa_drv_se_asymmetric_t));

    memset(p_key_mgmt_drv, 0, sizeof(psa_drv_se_key_management_t));
    memset(p_asymm_drv, 0, sizeof(psa_drv_se_asymmetric_t));
    p_key_mgmt_drv->p_generate             = &psa_alt_generate_key;
    p_key_mgmt_drv->p_allocate             = &psa_alt_allocate_key;
    p_key_mgmt_drv->p_export               = &psa_alt_export_key;
    p_key_mgmt_drv->p_destroy              = &psa_alt_destroy_key;
    p_key_mgmt_drv->p_import               = &psa_alt_import_key;
    p_key_mgmt_drv->p_validate_slot_number = &psa_alt_validate_slot_number;

    p_asymm_drv->p_sign    = &psa_alt_asymmetric_sign_digest;
    p_asymm_drv->p_verify  = &psa_alt_asymmetric_verify_digest;
    p_asymm_drv->p_encrypt = &psa_alt_asymmetric_encrypt;
    p_asymm_drv->p_decrypt = &psa_alt_asymmetric_decrypt;

    memset(p_driver, 0, sizeof(psa_drv_se_t));
    p_driver->hal_version    = PSA_DRV_SE_HAL_VERSION;
    p_driver->p_init         = &psa_alt_driver_init;
    p_driver->key_management = p_key_mgmt_drv;
    p_driver->asymmetric     = p_asymm_drv;
    /* doc:end:psa-assign-fp */

    /* First register SE Driver so that it is initialized in psa_crypto_init before performing any operation
     * Maximum of 4 drivers can be registered
     */

    LOG_I("Registering SE Driver");

    status = psa_register_se_driver(location, p_driver);
    ENSURE_OR_GO_EXIT(status == PSA_SUCCESS);

exit:
    return status;
}