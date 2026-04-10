#!/bin/bash
# Copyright 2019,2020 NXP
#
# NXP Confidential. This software is owned or controlled by NXP and may only
# be used strictly in accordance with the applicable license terms.  By
# expressly accepting such terms or by downloading, installing, activating
# and/or otherwise using the software, you are agreeing that you have read,
# and that you agree to comply with and are bound by, such license terms.  If
# you do not agree to be bound by the applicable license terms, then you may
# not retain, install, activate or otherwise use the software.
#

# UTILITY FUNCTIONS
# -----------------
# python openssl_provisionEC.py --key_type prime192v1 --connection_type jrcpv2 --connection_data /var/run/am
# python openssl_Ecdh.py --key_type prime192v1 --connection_data /var/run/am
# python openssl_EccSign.py --key_type prime192v1 --connection_data /var/run/am
# python openssl_rnd.py
#


ec_curve=(
  "prime192v1"
  "secp224r1"
  "prime256v1"
  "secp384r1"
  "secp521r1"
  "brainpoolP160r1"
  "brainpoolP192r1"
  "brainpoolP224r1"
  "brainpoolP256r1"
  "brainpoolP320r1"
  "brainpoolP384r1"
  "brainpoolP512r1"
  "secp160k1"
  "secp192k1"
  "secp224k1"
  "secp256k1"
  )

for cure in "${ec_curve[@]}"; do
  echo "%%%%%%%%%%%%%%%%%%%%%%%%%"
  python3 openssl_provisionEC.py --key_type ${cure} --connection_type jrcpv1 --connection_data /var/run/am
  python3 openssl_Ecdh.py --key_type ${cure} --connection_data /var/run/am &
  python3 openssl_EccSign.py --key_type ${cure} --connection_data /var/run/am &
  wait
  local nRetProc="$?"
  if [ ${nRetProc} -ne 0 ]; then
    echo "Test Failed, returned ${nRetProc}"
    exit 2
  fi
done


python3 openssl_rnd.py
