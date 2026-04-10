#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

credentials = {
    "DEVICE_KEY": "",
    "GATEWAY_KEY": "",
    "GATEWAY_CERT": "",
    "DEVICE_REF_KEY": "",
    "DEVICE_CERT": "",
    "INTERM_CA_CERT": "",
    "INTERM_CA_KEY": "",
    "ROOT_CA_KEY": "",
    "ROOT_CA_CERT_CER": "",
    "ROOT_CA_CERT_CRT": "",
}


def create_credentials(uid):
    credentials["DEVICE_KEY"] = "%d_device_key.pem" % uid
    credentials["DEVICE_REF_KEY"] = "%d_device_reference_key.pem" % uid
    credentials["DEVICE_CERT"] = "%d_device_certificate.cer" % uid
    credentials["GATEWAY_KEY"] = "%d_gateway_key.pem" % uid
    credentials["GATEWAY_CERT"] = "%d_gateway_certificate.crt" % uid
    credentials["INTERM_CA_CERT"] = "interCA_certificate.cer"
    credentials["INTERM_CA_KEY"] = "interCA_key.pem"
    credentials["ROOT_CA_KEY"] = "rootCA_key.pem"
    credentials["ROOT_CA_CERT_CER"] = "rootCA_certificate.cer"
    credentials["ROOT_CA_CERT_CRT"] = "rootCA_certificate.crt"
    return credentials
