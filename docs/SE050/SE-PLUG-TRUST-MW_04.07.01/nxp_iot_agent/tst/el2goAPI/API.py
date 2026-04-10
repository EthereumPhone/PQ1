# Copyright 2024 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

import requests
from .AlgorithmType import AlgorithmType
from .PolicySourceType import PolicySourceType
from .CertificateValidity import CertificateValidity
from .ProductHardwareFamilyType import ProductHardwareFamilyType

#---------------------------------------------------------------------------------
#-------------------------------- Global variables -------------------------------
#---------------------------------------------------------------------------------

__api_url: str = "https://api.edgelock2go.com/api/v1"




#---------------------------------------------------------------------------------
#------------------------------------ Generic ------------------------------------
#---------------------------------------------------------------------------------

def __getHttpHeader(api_key: str) -> dict[str, str]:
    """
    Returns the HTTP Header for the API connection
    """

    global __api_key
    return {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'EL2G-API-Key': api_key
    }

def __combineURLs(url_path: str) -> str:
    """
    Combine an URL with a URL-path.

    @param url_path: path at the end of an URL

    Returns the combied URL
    """

    global __api_url
    return __api_url + (url_path if (url_path[0] == '/') else ("/" + url_path))

def getAPIUrl() -> str:
    """
    Returns the API URL used for the connection
    """

    global __api_url
    return __api_url

def setAPIUrl(api_url: str = "https://api.edgelock2go.com/api/v1") -> None:
    """
    Sets the API URL which is used to connect to the API.

    @api_url: new API URL (default: https://api.edgelock2go.com/api/v1)
    """

    global __api_url
    if(api_url[-1] == '/'):
        __api_url = api_url[:-1]
    else:
        __api_url = api_url


#---------------------------------------------------------------------------------
#----------------------------------- API calls -----------------------------------
#---------------------------------------------------------------------------------

def __api_call_post(api_key: str, url_path: str, params: dict = {}, timeout: int = 30) -> requests.Response:
    """
    Sends a POST request to the API at the api_url.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param url_path: path at the end of an URL
    @param params: additional parameters to send with the request
    @param timeout: maximum time to wait for the request (default: 30 seconds)

    Returns the response of the server
    """
    
    return requests.post(url=__combineURLs(url_path), headers=__getHttpHeader(api_key), json=params, timeout=timeout)

def __api_call_put(api_key: str, url_path: str, params: dict = {}, timeout: int = 30) -> requests.Response:
    """
    Sends a PUT request to the API at the api_url.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param url_path: path at the end of an URL
    @param params: additional parameters to send with the request
    @param timeout: maximum time to wait for the request (default: 30 seconds)

    Returns the response of the server
    """

    return requests.put(url=__combineURLs(url_path), headers=__getHttpHeader(api_key), json=params, timeout=timeout)

def __api_call_get(api_key: str, url_path: str, params: dict = {}, timeout: int = 30) -> requests.Response:
    """
    Sends a GET request to the API at the api_url.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param url_path: path at the end of an URL
    @param params: additional parameters to send with the request
    @param timeout: maximum time to wait for the request (default: 30 seconds)

    Returns the response of the server
    """

    return requests.get(url=__combineURLs(url_path), headers=__getHttpHeader(api_key), json=params, timeout=timeout)

def __api_call_delete(api_key: str, url_path: str, params: dict = {}, timeout: int = 30) -> requests.Response:
    """
    Sends a DELETE request to the API at the api_url.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param url_path: path at the end of an URL
    @param params: additional parameters to send with the request
    @param timeout: maximum time to wait for the request (default: 30 seconds)

    Returns the response of the server
    """

    return requests.delete(url=__combineURLs(url_path), headers=__getHttpHeader(api_key), json=params, timeout=timeout)



#---------------------------------------------------------------------------------
#--------------------------------- API functions ---------------------------------
#---------------------------------------------------------------------------------

def createDeviceGroup(api_key: str, nc12: str, device_group_name: str) -> requests.Response:
    """
    Create a new device group.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param nc12: 12NC of the MCU/MPU or the secure element
    @param device_group_name: name of the device group thats going to be created

    Returns the response of the server
    """

    params = {
        "deviceGroupName": device_group_name
    }

    return __api_call_post(api_key, f"/products/{nc12}/device-groups", params)


def addDevicesToDeviceGroup(api_key: str, nc12: str, device_group_id: int, device_ids: list[str]) -> requests.Response:
    """
    Add a list of devices to a device group.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param nc12: 12NC of the MCU/MPU or the secure element
    @param device_group_id: id of the device group
    @param device_ids: list of device ids which should be added to the device group

    Returns the response of the server
    """

    params = {
        "deviceIds": device_ids
    }

    return __api_call_post(api_key, f"/products/{nc12}/device-groups/{device_group_id}/devices", params)


def addDeviceToDeviceGroup(api_key: str, nc12: str, device_group_id: int, device_id: str) -> requests.Response:
    """
    Add a device to a device group.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param nc12: 12NC of the MCU/MPU or the secure element
    @param device_group_id: id of the device group
    @param device_id: device id which should be added to the device group

    Returns the response of the server
    """

    params = {
        "deviceIds": [
            device_id
        ]
    }

    return __api_call_post(api_key, f"/products/{nc12}/device-groups/{device_group_id}/devices", params)


def createKeypair(api_key: str, keypair_name: str, object_id: str,
                  algorithm: AlgorithmType, generate_on_device_connection: bool = False,
                  policy_source_type: PolicySourceType = PolicySourceType.DEFAULT,
                  policies: dict = None) -> requests.Response:
    """
    Generates a keypair secure object.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param keypair_name: Name of the keypair thats going to be generated
    @param object_id: Object identification, validation rules are enforced on server side!
    @param algorithm: Algorithm used to generate the keypair
    @param generate_on_device_connection: Generate secure object on device connection (default: False)
    @param policy_source_type: Defines which policy is used (default: DEFAULT)
    @param policies: Custom defined policies (default: None)

    Returns the response of the server
    """

    params = {
        "name": keypair_name,
        "algorithm": algorithm.name,
        "secureObjectType": "KEYPAIR",
        "objectId": object_id,
        "generateOnDeviceConnection": generate_on_device_connection,
        "policySourceType": policy_source_type.name,
        "policies": policies
    }

    return __api_call_post(api_key, "/rtp/secure-objects", params)


def createX509Certificate(api_key: str, certificate_name: str, object_id: str, common_name_prefix: str,
                          keypair_id: int, intermediate_ca_id: int, certificate_validity: CertificateValidity = CertificateValidity(),
                          allow_signing: bool = True, generate_on_device_connection: bool = False,
                          policy_source_type: PolicySourceType = PolicySourceType.DEFAULT,
                          policies: dict = None) -> requests.Response:
    """
    Generates X509 Certificate.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param certificate_name: Name of the certificate thats going to be generated
    @param object_id: Object identification, validation rules are enforced on server side!
    @param common_name_prefix: Define the value of the certificate common name.
    @param keypair_id: Id of the keypair used in the certificate
    @param intermediate_ca_id: Id of the certificate used to sign the X509 certificate
    @param certificate_validity: Time in which the certificate is valid (default: 10 Years - will not exceed validity of CA)
    @param allow_signing: Allow signing (default: True)
    @param generate_on_device_connection: Generate secure object on device connection (default: False)
    @param policy_source_type: Defines which policy is used (default: DEFAULT)
    @param policies: Custom defined policies (default: None)

    Returns the response of the server
    """

    params = {
        "name": certificate_name,
        "secureObjectType": "CERTIFICATE",
        "keyPairId": keypair_id,
        "intermediateCaId": intermediate_ca_id,
        "commonNamePrefix": common_name_prefix,
        "objectId": object_id,
        "certificateValidity": certificate_validity.getJsonFormat(),
        "allowSigning": allow_signing,
        "generateOnDeviceConnection": generate_on_device_connection,
        "policySourceType": policy_source_type.name,
        "policies": policies
    }

    return __api_call_post(api_key, "/rtp/secure-objects", params)


def createAESMasterKey(api_key: str,) -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    params = {"""
        "name": aes_master_key_name,
        "secureObjectType": "MASTER_KEY",
        "objectId": object_id,
        "keySize":"AES256",
        "customerPgpPublicKey": "<your_PGP_public_key>",
        "encryptedKey": "<PGP_encrypted_AES_key>",
        "generateOnDeviceConnection": generate_on_device_connection,
        "policySourceType": policy_source_type.name,
        "policies": policies"""
    }

    return __api_call_post(api_key, "/rtp/secure-objects", params)


def createHMACMasterKey(api_key: str, hmac_master_key_name: str, object_id: str,
                        encrypted_key: str, PGP_public_key: str, key_size: int = 256,
                        generate_on_device_connection: bool = False,
                        policy_source_type: PolicySourceType = PolicySourceType.DEFAULT,
                        policies: dict = None) -> requests.Response:
    """
    Generates a HMAC master key.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param hmac_master_key_name: Name of the HMAC master key thats going to be generated
    @param object_id: Object identification, validation rules are enforced on server side!
    @param encrypted_key: PGP encrypted HMAC key
    @param PGP_public_key: PGP public key
    @param key_size: Size of the key (default: 256, range: 1 - 256)
    @param generate_on_device_connection: Generate secure object on device connection (default: False)
    @param policy_source_type: Defines which policy is used (default: DEFAULT)
    @param policies: Custom defined policies (default: None)

    Returns the response of the server
    """

    params = {
        "name": hmac_master_key_name,
        "secureObjectType": "HMAC_KEY",
        "objectId": object_id,
        "keySize": key_size,
        "customerPgpPublicKey": PGP_public_key,
        "encryptedKey": encrypted_key,
        "generateOnDeviceConnection": generate_on_device_connection,
        "policySourceType": policy_source_type.name,
        "policies": policies
    }

    return __api_call_post(api_key, "/rtp/secure-objects", params)


def createNonConfidentialBinaryFile(api_key: str, binary_file_name: str, object_id: str,
                                    binary_file_payload: str, sha3_512_checksum: str = None,
                                    generate_on_device_connection: bool = False,
                                    policy_source_type: PolicySourceType = PolicySourceType.DEFAULT,
                                    policies: dict = None) -> requests.Response:
    """
    Generates a non confidential binary file secure object.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param binary_file_name: Name of the secure object thats going to be generated
    @param object_id: Object identification, validation rules are enforced on server side!
    @param binary_file_payload: Payload of a binary file in base-64 format
    @param sha3_512_checksum: SHA3-512 checksum of the payload (default: None)
    @param generate_on_device_connection: Generate secure object on device connection (default: False)
    @param policy_source_type: Defines which policy is used (default: DEFAULT)
    @param policies: Custom defined policies (default: None)

    Returns the response of the server
    """

    params = {
        "name": binary_file_name,
        "secureObjectType": "BINARY_FILE",
        "objectId": object_id,
        "payload": {
            "binaryFileType": "NON_CONFIDENTIAL",
            "binaryFile": binary_file_payload
        },
        "generateOnDeviceConnection": generate_on_device_connection,
        "policySourceType": policy_source_type.name,
        "policies": policies
    }

    if(sha3_512_checksum != None):
        params["payload"]["checkSum"] = sha3_512_checksum

    return __api_call_post(api_key, "/rtp/secure-objects", params)


def createConfidentialBinaryFile(api_key: str, binary_file_name: str, object_id: str,
                                 encrypted_binary_file_payload: str, PGP_public_key: str,
                                 generate_on_device_connection: bool = False,
                                 policy_source_type: PolicySourceType = PolicySourceType.DEFAULT,
                                 policies: dict = None) -> requests.Response:
    """
    Generates a confidential binary file secure object.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param binary_file_name: Name of the secure object thats going to be generated
    @param object_id: Object identification, validation rules are enforced on server side!
    @param encrypted_binary_file_payload: PGP encrypted binary file
    @param PGP_public_key: PGP public key
    @param generate_on_device_connection: Generate secure object on device connection (default: False)
    @param policy_source_type: Defines which policy is used (default: DEFAULT)
    @param policies: Custom defined policies (default: None)

    Returns the response of the server
    """

    params = {
        "name": binary_file_name,
        "secureObjectType": "BINARY_FILE",
        "objectId": object_id,
        "payload": {
            "binaryFileType": "CONFIDENTIAL",
            "customerPgpPublicKey": PGP_public_key,
            "encryptedBinaryFile": encrypted_binary_file_payload
        },
        "generateOnDeviceConnection": generate_on_device_connection,
        "policySourceType": policy_source_type.name,
        "policies": policies
    }

    return __api_call_post(api_key, "/rtp/secure-objects", params)


def createStaticPublicKey(api_key: str, public_static_key_name: str, object_id: str,
                          public_key: str, sha3_512_checksum: str = None,
                          algorithm: AlgorithmType = AlgorithmType.RSA_2048,
                          generate_on_device_connection: bool = False,
                          policy_source_type: PolicySourceType = PolicySourceType.DEFAULT,
                          policies: dict = None) -> requests.Response:
    """
    Generates a static public key.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param public_static_key_name: Name of the public static key thats going to be generated
    @param object_id: Object identification, validation rules are enforced on server side!
    @param public_key: Public key in BEM format
    @param sha3_512_checksum: SHA3-512 checksum of the key
    @param generate_on_device_connection: Generate secure object on device connection (default: False)
    @param policy_source_type: Defines which policy is used (default: DEFAULT)
    @param policies: Custom defined policies (default: None)

    Returns the response of the server
    """

    params = {
        "name": public_static_key_name, 
        "secureObjectType": "STATIC_PUBLIC_KEY",
        "objectId": object_id,
        "publicKey": public_key,
        "algorithm": algorithm.name,
        "generateOnDeviceConnection": generate_on_device_connection,
        "policySourceType": policy_source_type.name,
        "policies": policies
    }

    if(sha3_512_checksum != None):
        params["checkSum"] = sha3_512_checksum

    return __api_call_post(api_key, "/rtp/secure-objects", params)


def createOEMFWAuthenticationKeyHash(api_key: str, oem_key_hash_name: str, object_id: str,
                                     binary_file_payload: str, oem_provisioned: bool = True,
                                     generate_on_device_connection: bool = False,
                                     policy_source_type: PolicySourceType = PolicySourceType.DEFAULT,
                                     policies: dict = None) -> requests.Response:
    """
    Generates a OEM FW Authentication Key Hash.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param oem_key_hash_name: Name of the key hash thats going to be generated
    @param object_id: Object identification, validation rules are enforced on server side!
    @param binary_file_payload: Payload of a binary file in base-64 format
    @param oem_provisioned: Defines if the hash is OEM provisioned (default: False)
    @param generate_on_device_connection: Generate secure object on device connection (default: False)
    @param policy_source_type: Defines which policy is used (default: DEFAULT)
    @param policies: Custom defined policies (default: None)

    Returns the response of the server
    """

    params = {
        "name": oem_key_hash_name,
        "secureObjectType": "OEM_FW_AUTH_KEY_HASH",
        "objectId": object_id,
        "binaryFile": binary_file_payload,
        "oemProvisioned": oem_provisioned,
        "generateOnDeviceConnection": generate_on_device_connection,
        "policySourceType": policy_source_type.name,
        "policies": policies
    }

    return __api_call_post(api_key, "/rtp/secure-objects", params)


def createOEMFWDecryptionKey(api_key: str, oem_decryption_key_name: str, object_id: str,
                             encrypted_key: str, PGP_public_key: str, key_size: str = "AES256",
                             generate_on_device_connection: bool = False,
                             policy_source_type: PolicySourceType = PolicySourceType.DEFAULT,
                             policies: dict = None) -> requests.Response:
    """
    Generates a OEM FW Decryption Key.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param oem_decryption_key_name: Name of the decryption key thats going to be generated
    @param object_id: Object identification, validation rules are enforced on server side!
    @param encrypted_key: Encrypted decryption key
    @param PGP_public_key: PGP public key
    @param key_size: Size of the encrypted key
    @param generate_on_device_connection: Generate secure object on device connection (default: False)
    @param policy_source_type: Defines which policy is used (default: DEFAULT)
    @param policies: Custom defined policies (default: None)

    Returns the response of the server
    """

    params = {
        "name": oem_decryption_key_name,
        "secureObjectType": "OEM_FW_DECRYPT_KEY",
        "objectId": object_id,
        "keySize": key_size,
        "encryptedKey": encrypted_key,
        "customerPgpPublicKey": PGP_public_key,
        "generateOnDeviceConnection": generate_on_device_connection,
        "policySourceType": policy_source_type.name,
        "policies": policies
    }

    return __api_call_post(api_key, "/rtp/secure-objects", params)


def assignSecureObjectToDeviceGroup(api_key: str, device_group_id: int, 
                                    secure_object_id: int, 
                                    product_hw_family_type: ProductHardwareFamilyType = ProductHardwareFamilyType.RW6) -> requests.Response:
    """
    Assigns a secure object to a device group

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param device_group_id: Id of a device group
    @param secure_object_id: Id of a secure object
    @param product_hw_family_type: Hardware family type of the device group (default: RW6)

    Returns the response of the server
    """

    params = {
        "deviceGroupId": device_group_id
    }

    if(product_hw_family_type != None):
        params["productHardwareFamilyType"] = product_hw_family_type.name

    return __api_call_post(api_key, f"/rtp/secure-objects/{secure_object_id}/assign-device-group", params)


def downloadSecureObjectProvisioningFile() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("downloadSecureObjectProvisioningFile: NOT IMPLEMENTED YET!")


def uploadExternalIntermediateCertificate() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("uploadExternalIntermediateCertificate: NOT IMPLEMENTED YET!")


def createCSRforIntermediateCertificate() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("createCSRforIntermediateCertificate: NOT IMPLEMENTED YET!")


def retrieveCSRValue() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveCSRValue: NOT IMPLEMENTED YET!")


def uploadIntermediateCertificateSignedByExternalCA() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("uploadIntermediateCertificateSignedByExternalCA: NOT IMPLEMENTED YET!")


def retrieveProducts() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveProducts: NOT IMPLEMENTED YET!")


def retrieveHardwareTypes() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveHardwareTypes: NOT IMPLEMENTED YET!")


def retrieveDevelopmentBoards() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveDevelopmentBoards: NOT IMPLEMENTED YET!")


def retrieveDeviceGroups(nc12: str) -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveDeviceGroups: NOT IMPLEMENTED YET!")


def retrieveDeviceGroupByID(nc12: str, device_group_id: int) -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveDeviceGroupByID: NOT IMPLEMENTED YET!")


def retrieveDeviceData(nc12: str, device_group_id: int, device_id: int) -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveDeviceData: NOT IMPLEMENTED YET!")


def retrieveDevicesAssignedToDeviceGroup(nc12: str, device_group_id: int) -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveDevicesAssignedToDeviceGroup: NOT IMPLEMENTED YET!")


def unclaimDevicesFromDeviceGroup(api_key: str, nc12: str, device_group_id: int, device_ids: list[str]) -> requests.Response:
    """
    Removes a list devices from a device group.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param nc12: 12NC of the MCU/MPU or the secure element
    @param device_group_id: id of the device group
    @params device_ids: list of device ids which should be removed from the group

    Returns the response of the server
    """

    params = {
        "deviceIds": device_ids
    }

    return __api_call_post(api_key, f"/products/{nc12}/device-groups/{device_group_id}/devices/unclaim", params)


def unclaimDeviceFromDeviceGroup(api_key: str, nc12: str, device_group_id: int, device_id: str) -> requests.Response:
    """
    Removes a device from a device group.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param nc12: 12NC of the MCU/MPU or the secure element
    @param device_group_id: id of the device group
    @params device_id: device id which should be removed from the group

    Returns the response of the server
    """

    params = {
        "deviceIds": [
            device_id
        ]
    }

    return __api_call_post(api_key, f"/products/{nc12}/device-groups/{device_group_id}/devices/unclaim", params)


def unclaimAllDevicesFromDeviceGroup(api_key: str, nc12: str, device_group_id: int) -> requests.Response:
    """
    Removes all devices from a device group.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param nc12: 12NC of the MCU/MPU or the secure element
    @param device_group_id: id of the device group

    Returns the response of the server
    """

    return __api_call_post(api_key, f"/products/{nc12}/device-groups/{device_group_id}/unclaim")


def deleteDeviceGroup(api_key: str, nc12: str, device_group_id: int) -> requests.Response:
    """
    Delete a device group.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param nc12: 12NC of the MCU/MPU or the secure element
    @param device_group_id: id of the device group

    Returns the response of the server
    """

    return __api_call_delete(api_key, f"/products/{nc12}/device-groups/{device_group_id}")


def updateDeviceGroupName(api_key: str, nc12: str, device_group_id: int, device_group_name: str) -> requests.Response:
    """
    Update the name of a device group.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param nc12: 12NC of the MCU/MPU or the secure element
    @param device_group_id: id of the device group
    @param device_group_name: new name of the device group

    Returns the response of the server
    """

    params = {
        "deviceGroupName": device_group_name
    }

    return __api_call_put(api_key, f"/products/{nc12}/device-groups/{device_group_id}", params)


def assignClaimCodeToDeviceGroup(api_key: str, nc12: str, device_group_id: int,
                                 claim_code_name: str, claim_code_secret: str, 
                                 device_limit: int = 0, device_count: int = 100, reusable: bool = True,
                                 behavior: str = "ALLOW", policy: str = "UNRESTRICTED", status: str ="ALL") -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    params = {
        "name": claim_code_name,
        "behavior": behavior,
        "deviceLimit": device_limit,
        "reusable": reusable,
        "secret": claim_code_secret,
        "deviceCount": device_count,
        "policy": policy,
        "status": status
    }

    return __api_call_post(api_key, f"/products/{nc12}/device-groups/{device_group_id}/claim-codes", params)


def createBatchOfClaimCodes() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("crateBatchOfClaimCodes: NOT IMPLEMENTED YET!")


def retrieveDetailsOfBatchOfClaimCodes() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveDetailsOfBatchOfClaimCodes: NOT IMPLEMENTED YET!")


def retrieveClaimCodesOfDeviceGroup() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveClaimCodesOfDeviceGroup: NOT IMPLEMENTED YET!")


def retrieveClaimCodeByID() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveClaimCodeByID: NOT IMPLEMENTED YET!")


def updateClaimCode() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("updateClaimCode: NOT IMPLEMENTED YET!")


def revokeClaimCode() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("revokeClaimCode: NOT IMPLEMENTED YET!")


def retrieveDecryptedSecretOfClaimCode() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveDecryptedSecretOfClaimCode: NOT IMPLEMENTED YET!")


def deleteClaimCode() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("deleteClaimCode: NOT IMPLEMENTED YET!")


def deleteClaimCodesByCriteria() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("deleteClaimCodesByCriteria: NOT IMPLEMENTED YET!")


def retrieveGroupedClaimCodeStatistics() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveGroupedClaimCodeStatistics: NOT IMPLEMENTED YET!")


def downloadOEMFirmwareAuthKeyHash() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("downloadOEMFirmwareAuthKeyHash: NOT IMPLEMENTED YET!")


def retrieveSecureObjectProvisionings() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveSecureObjectProvisionings: NOT IMPLEMENTED YET!")


def retrieveDeviceGroups(): # <----- change name
    """
    NOT IMPLEMENTED YET!
    """

    print(": NOT IMPLEMENTED YET!")


def unassignSecureObjectFromDeviceGroups(api_key: str, device_group_ids: list[int], 
                                         secure_object_id: int, 
                                         product_hw_family_type: ProductHardwareFamilyType = ProductHardwareFamilyType.RW6) -> requests.Response:
    """
    Unassign a secure object from multiple device groups

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param device_group_ids: List of ids of the device groups
    @param secure_object_id: Id of a secure object
    @param product_hw_family_type: Hardware family type of the device group (default: RW6)

    Returns the response of the server
    """

    params = []
    for id in device_group_ids:
        temp = {
            "deviceGroupId": id
        }

        if(product_hw_family_type != None):
            temp["productHardwareFamilyType"] = product_hw_family_type.name
        
        params.append(temp)

    return __api_call_post(api_key, f"/rtp/secure-objects/{secure_object_id}/unassign-device-groups/?hardware-family-type={product_hw_family_type.name}", params)


def unassignSecureObjectFromDeviceGroup(api_key: str, device_group_id: int, 
                                        secure_object_id: int, 
                                        product_hw_family_type: ProductHardwareFamilyType = ProductHardwareFamilyType.RW6) -> requests.Response:
    """
    Unassign a secure object from a device group

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param device_group_id: Id of a device group
    @param secure_object_id: Id of a secure object
    @param product_hw_family_type: Hardware family type of the device group (default: RW6)

    Returns the response of the server
    """

    return unassignSecureObjectFromDeviceGroups(api_key, [device_group_id], secure_object_id, product_hw_family_type)

def unassignListOfSecureObjectsFromDeviceGroup(api_key: str, device_group_id: int, 
                                               secure_object_ids: list[int], 
                                               product_hw_family_type: ProductHardwareFamilyType = ProductHardwareFamilyType.RW6) -> requests.Response:
    """
    Unassign a list secure objects from a device group

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param device_group_id: Id of a device group
    @param secure_object_ids: List of ids of the secure objects
    @param product_hw_family_type: Hardware family type of the device group (default: RW6)

    Returns the response of the server
    """

    params = secure_object_ids

    return __api_call_post(api_key, f"/rtp/device-groups/{device_group_id}/unassign-secure-objects/?hardware-family-type={product_hw_family_type.name}", params)


def retrieveSecureObjectByID(api_key: str, secure_object_id: int) -> requests.Response:
    """
    Get the details of a secure object.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param secure_object_id: Id of a secure object

    Returns the response of the server
    """

    return __api_call_get(api_key, f"/rtp/secure-objects/{secure_object_id}")


def retrieveAllSecureObjects() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveAllSecureObjects: NOT IMPLEMENTED YET!")


def retrieveSecureObjectsAssignedToDeviceGroup() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveSecureObjectsAssignedToDeviceGroup: NOT IMPLEMENTED YET!")


def retrieveSecureObjectsThatCanBeAssignedToDeviceGroup():  # <----- change name
    """
    NOT IMPLEMENTED YET!
    """

    print(": NOT IMPLEMENTED YET!")


def retrieveDeviceGroupsAssignedToSecureObject() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveDeviceGroupsAssignedToSecureObject: NOT IMPLEMENTED YET!")


def retrieveProvisioningsOfSecureObject() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveProvisioningsOfSecureObject: NOT IMPLEMENTED YET!")


def retrieveProvisioningsOfDevice(api_key: str, device_id: str, hardware_family: ProductHardwareFamilyType = ProductHardwareFamilyType.RW6) -> requests.Response:
    """
    Rretrieve the provisioning details of a device.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param device_id: Id of the device
    @param hardware_family: Hardware family of the device (default: RW6)

    Returns the response of the server
    """

    return __api_call_get(api_key, f"/rtp/devices/{device_id}/secure-object-provisionings/?hardware-family-type={hardware_family.name}")


def downloadCertificateOfX509() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("downloadCertificateOfX509: NOT IMPLEMENTED YET!")


def deleteSecureObject(api_key: str, secure_object_id: int) -> requests.Response:
    """
    Delete a secure object.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param secure_object_id: Id of a secure object

    Returns the response of the server
    """

    return __api_call_delete(api_key, f"/rtp/secure-objects/{secure_object_id}")


def updateSecureObject() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("updateSecureObject: NOT IMPLEMENTED YET!")


def retrievePoliciesOfSecureObject() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrievePoliciesOfSecureObject: NOT IMPLEMENTED YET!")


def retrieveDefaultUsagePolicyOfSecureObject() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveDefaultUsagePolicyOfSecureObject: NOT IMPLEMENTED YET!")


def retrieveOIDValidationRules() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveOIDValidationRules: NOT IMPLEMENTED YET!")


def createIntermediateCertificateSignedByNXPRootCA(api_key: str, certificate_name: str, prefix: str,
                                                   algorithm: AlgorithmType = AlgorithmType.NIST_P256,  include_authority_key_id: bool = True, 
                                                   include_subject_key_id: bool = True) -> requests.Response:
    """
    Generates a new intermediate certificate in Edgelock 2GO signed by either NXP root certificate.
    If the generation is successful, the intermediate certificate can be used to sign X509 certificate secure objects.

    @param api_key: API Key of Edgelock2Go (generate here: https://edgelock2go.com/company-settings)
    @param certificate_name: The desired name of the created certificate
    @param prefix: The prefix of the certificate
    @param algorithm: Defines which algorithm should be used to create the certificate (default: NIST_P256)
    @param include_authority_key_id: Sets if the authority key id should be included in the certificate (default: true)
    @param include_subject_key_id: Sets if the subject key id should be included in the certificate (default: true)

    Returns the response of the server
    """

    params = {
        "name": certificate_name,
        "algorithm": algorithm.name,
        "requestType": "WITHOUT_CSR",
        "prefix": prefix,
        "includeAuthorityKeyIdentifier": include_authority_key_id,
        "includeSubjectKeyIdentifier": include_subject_key_id
    }

    return __api_call_post(api_key, "/rtp/intermediate-cas", params)


def retrieveIntermediateCertificateByID() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveIntermediateCertificateByID: NOT IMPLEMENTED YET!")


def retrieveAllIntermediateCertificates() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveAllIntermediateCertificates: NOT IMPLEMENTED YET!")


def downloadIntermediateCertificate() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("downloadIntermediateCertificate: NOT IMPLEMENTED YET!")


def createVerificationCertificateSignedByIntermediateCA() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("createVerificationCertificateSignedByIntermediateCA: NOT IMPLEMENTED YET!")


def retrieveSecureObjectsAssignedToIntermediateCertificate() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveSecureObjectsAssignedToIntermediateCertificate: NOT IMPLEMENTED YET!")


def deleteIntermediateCertificate() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("deleteIntermediateCertificate: NOT IMPLEMENTED YET!")


def retrieveSupportedAlgorithms() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("retrieveSupportedAlgorithms: NOT IMPLEMENTED YET!")


def generateActivityReport() -> requests.Response:
    """
    NOT IMPLEMENTED YET!
    """

    print("generateActivityReport: NOT IMPLEMENTED YET!")







