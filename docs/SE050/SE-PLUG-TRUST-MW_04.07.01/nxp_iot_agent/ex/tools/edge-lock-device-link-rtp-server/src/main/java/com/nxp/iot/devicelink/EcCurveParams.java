/*
 * Copyright 2020-2021 NXP.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.nxp.iot.devicelink;

import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.List;

public class EcCurveParams {

	private EcCurveParams() {
	}

	private static final String SECP192R1 = "SECP192R1";
	private static final String SECP224R1 = "SECP224R1";
	private static final String SECP256R1 = "SECP256R1";
	private static final String SECP384R1 = "SECP384R1";
	private static final String SECP521R1 = "SECP521R1";
	private static final String NIST_P192 = "NIST_P192";
	private static final String NIST_P224 = "NIST_P224";
	private static final String NIST_P256 = "NIST_P256";
	private static final String NIST_P384 = "NIST_P384";
	private static final String NIST_P521 = "NIST_P521";
	private static final String BRAINPOOLP160R1 = "BRAINPOOLP160R1";
	private static final String BRAINPOOLP192R1 = "BRAINPOOLP192R1";
	private static final String BRAINPOOLP224R1 = "BRAINPOOLP224R1";
	private static final String BRAINPOOLP256R1 = "BRAINPOOLP256R1";
	private static final String BRAINPOOLP320R1 = "BRAINPOOLP320R1";
	private static final String BRAINPOOLP384R1 = "BRAINPOOLP384R1";
	private static final String BRAINPOOLP512R1 = "BRAINPOOLP512R1";
	private static final String SECP160K1 = "SECP160K1";
	private static final String SECP192K1 = "SECP192K1";
	private static final String SECP224K1 = "SECP224K1";
	private static final String SECP256K1 = "SECP256K1";
	private static final String ID_ECC_ED_25519 = "ID_ECC_ED_25519";
	private static final String ID_ECC_MONT_DH_25519 = "ID_ECC_MONT_DH_25519";
	private static final String ID_ECC_MONT_DH_448 = "ID_ECC_MONT_DH_448";
	private static final String ECC_ED_25519 = "ECC_ED_25519";
	private static final String ECC_MONT_DH_25519 = "ECC_MONT_DH_25519";
	private static final String ECC_MONT_DH_448 = "ECC_MONT_DH_448";
	private static final String RSA_1024 = "RSA_1024";
	private static final String RSA_2048 = "RSA_2048";
	private static final String RSA_3072 = "RSA_3072";
	private static final String RSA_4096 = "RSA_4096";
	private static final String RSA_1024_CRT = "RSA_1024_CRT";
	private static final String RSA_2048_CRT = "RSA_2048_CRT";
	private static final String RSA_3072_CRT = "RSA_3072_CRT";
	private static final String RSA_4096_CRT = "RSA_4096_CRT";

	@SuppressWarnings("checkstyle:TypeName")
	public enum ECCurve {
		UNUSED(0x00),
		NIST_P192(0x01),
		NIST_P224(0x02),
		NIST_P256(0x03),
		NIST_P384(0x04),
		NIST_P521(0x05),
		BRAINPOOL160(0x06),
		BRAINPOOL192(0x07),
		BRAINPOOL224(0x08),
		BRAINPOOL256(0x09),
		BRAINPOOL320(0x0A),
		BRAINPOOL384(0x0B),
		BRAINPOOL512(0x0C),
		SECP160K1(0x0D),
		SECP192K1(0x0E),
		SECP224K1(0x0F),
		SECP256K1(0x10),
		TPM_ECC_BN_P256(0x11),
		ID_ECC_ED_25519(0x40),
		ID_ECC_MONT_DH_25519(0x41),
		ID_ECC_MONT_DH_448(0x43),
		;
		public final int value;

		ECCurve(int value) {
			this.value = value;
		}
	}

	/**
	 * Returns EcCurve for a given algorithm..
	 *
	 * @param algorithm KeyPair algorithm
	 * @return EcCurve
	 */
	public static ECCurve getEcCurveIndex(String algorithm) {
		switch (algorithm) {
			case SECP192R1:
			case NIST_P192:
				return ECCurve.NIST_P192;
			case SECP224R1:
			case NIST_P224:
				return ECCurve.NIST_P224;
			case SECP256R1:
			case NIST_P256:
				return ECCurve.NIST_P256;
			case SECP384R1:
			case NIST_P384:
				return ECCurve.NIST_P384;
			case SECP521R1:
			case NIST_P521:
				return ECCurve.NIST_P521;
			case SECP160K1:
				return ECCurve.SECP160K1;
			case SECP192K1:
				return ECCurve.SECP192K1;
			case SECP224K1:
				return ECCurve.SECP224K1;
			case SECP256K1:
				return ECCurve.SECP256K1;
			case BRAINPOOLP160R1:
				return ECCurve.BRAINPOOL160;
			case BRAINPOOLP192R1:
				return ECCurve.BRAINPOOL192;
			case BRAINPOOLP224R1:
				return ECCurve.BRAINPOOL224;
			case BRAINPOOLP256R1:
				return ECCurve.BRAINPOOL256;
			case BRAINPOOLP320R1:
				return ECCurve.BRAINPOOL320;
			case BRAINPOOLP384R1:
				return ECCurve.BRAINPOOL384;
			case BRAINPOOLP512R1:
				return ECCurve.BRAINPOOL512;
			case ID_ECC_ED_25519:
			case ECC_ED_25519:
				return ECCurve.ID_ECC_ED_25519;
			case ID_ECC_MONT_DH_25519:
			case ECC_MONT_DH_25519:
				return ECCurve.ID_ECC_MONT_DH_25519;
			case ID_ECC_MONT_DH_448:
			case ECC_MONT_DH_448:
				return ECCurve.ID_ECC_MONT_DH_448;
			default:
				throw new InvalidParameterException(String.format("Invalid algorithm [%s] in read ec curve list", algorithm));
		}
	}

	/**
	 * Checks if given KeyPair algorithm requires EC curve to be installed in SE before importing EC keypair.
	 *
	 * @param algorithm KeyPair algorithm
	 * @return True if algorithm requires curve to be installed in SE
	 */
	public static boolean isEcKeyPair(String algorithm) {
		switch (algorithm) {
			case SECP192R1:
			case SECP224R1:
			case SECP256R1:
			case SECP384R1:
			case SECP521R1:
			case NIST_P192:
			case NIST_P224:
			case NIST_P256:
			case NIST_P384:
			case NIST_P521:
			case SECP160K1:
			case SECP192K1:
			case SECP224K1:
			case SECP256K1:
			case BRAINPOOLP160R1:
			case BRAINPOOLP192R1:
			case BRAINPOOLP224R1:
			case BRAINPOOLP256R1:
			case BRAINPOOLP320R1:
			case BRAINPOOLP384R1:
			case BRAINPOOLP512R1:
			case ID_ECC_ED_25519:
			case ID_ECC_MONT_DH_25519:
			case ID_ECC_MONT_DH_448:
			case ECC_ED_25519:
			case ECC_MONT_DH_25519:
			case ECC_MONT_DH_448:
				return true;
			case RSA_1024:
			case RSA_2048:
			case RSA_3072:
			case RSA_4096:
			case RSA_1024_CRT:
			case RSA_2048_CRT:
			case RSA_3072_CRT:
			case RSA_4096_CRT:
				return false;
			default:
				throw new IllegalArgumentException(String.format("Unsupported algorithm [%s].", algorithm));
		}
	}

	/**
	 * Return apdus to install ecCurve parameters.
	 *
	 * @param algorithm KeyPair algorithm
	 * @return  apdus to install ecCurve parameters.
	 */
	public static List<String> getInstallEcCurveAPdus(String algorithm) {
		switch (algorithm) {
			case SECP192R1:
			case NIST_P192:
				return ApduContainer.GET_SECP192R1_APDU;
			case SECP224R1:
			case NIST_P224:
				return ApduContainer.GET_SECP224R1_APDU;
			case SECP256R1:
			case NIST_P256:
				return ApduContainer.GET_SECP256R1_APDU;
			case SECP384R1:
			case NIST_P384:
				return ApduContainer.GET_SECP384R1_APDU;
			case SECP521R1:
			case NIST_P521:
				return ApduContainer.GET_SECP521R1_APDU;
			case SECP160K1:
				return ApduContainer.GET_SECP160K1_APDU;
			case SECP192K1:
				return ApduContainer.GET_SECP192K1_APDU;
			case SECP224K1:
				return ApduContainer.GET_SECP224K1_APDU;
			case SECP256K1:
				return ApduContainer.GET_SECP256K1_APDU;
			case BRAINPOOLP160R1:
				return ApduContainer.GET_BRAINPOOL160_APDU;
			case BRAINPOOLP192R1:
				return ApduContainer.GET_BRAINPOOL192_APDU;
			case BRAINPOOLP224R1:
				return ApduContainer.GET_BRAINPOOL224_APDU;
			case BRAINPOOLP256R1:
				return ApduContainer.GET_BRAINPOOL256_APDU;
			case BRAINPOOLP320R1:
				return ApduContainer.GET_BRAINPOOL320_APDU;
			case BRAINPOOLP384R1:
				return ApduContainer.GET_BRAINPOOL384_APDU;
			case BRAINPOOLP512R1:
				return ApduContainer.GET_BRAINPOOL512_APDU;
			case RSA_1024:
			case RSA_2048:
			case RSA_3072:
			case RSA_4096:
			case RSA_1024_CRT:
			case RSA_2048_CRT:
			case RSA_3072_CRT:
			case RSA_4096_CRT:
			case ID_ECC_ED_25519:
			case ECC_ED_25519:
				return new ArrayList<>();
			case ID_ECC_MONT_DH_25519:
			case ECC_MONT_DH_25519:
				return ApduContainer.GET_ID_ECC_MONT_DH_25519_APDU;
			case ID_ECC_MONT_DH_448:
			case ECC_MONT_DH_448:
				return ApduContainer.GET_ID_ECC_MONT_DH_448_APDU;
			default:
				throw new InvalidParameterException(String.format("Algorithm not supported: [%s]", algorithm));
		}
	}
}
