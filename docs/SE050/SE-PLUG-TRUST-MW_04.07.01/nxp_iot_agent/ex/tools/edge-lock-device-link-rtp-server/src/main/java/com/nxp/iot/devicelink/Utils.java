/*
 * Copyright 2020-2021,2024 NXP.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.nxp.iot.devicelink;

import java.nio.ByteBuffer;

public class Utils {
	private Utils() {
	}

	/**
	 * converts hex string to byte array.
	 */
	public static byte[] hexStringToByteArray(String hexString) {
		int len = hexString.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character.digit(hexString.charAt(i + 1), 16));
		}
		return data;
	}

	/**
	 * converts byte array to hex string.
	 */
	public static String byteArrayToHexString(byte[] bytes) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length * 2];

		for (int j = 0; j < bytes.length; ++j) {
			int v = bytes[j] & 255;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 15];
		}
		return new String(hexChars);
	}

	/**
	 * Returns int value from given byte array.
	 *
	 * @param memory Source byte to be converted to int
	 * @param pos    offset to start conversion
	 * @return int value
	 */
	public static int getInt(byte[] memory, int pos) {
		return ((int) memory[pos++] & 0xFF) << 24
				| ((int) memory[pos++] & 0xFF) << 16
				| ((int) memory[pos++] & 0xFF) << 8
				| (int) memory[pos] & 0xFF;
	}

	/**
	 * Returns trimmed byte array.
	 *
	 * @param src    Source byte to be trimmed
	 * @param offset offset to start trimming
	 * @param len    bytes to be trimmed
	 * @return trimmed byte array
	 */
	public static byte[] trimByteArray(byte[] src, int offset, int len) {
		if (offset + len > src.length) {
			throw new IllegalArgumentException("Trimmed byte array is outside of source array");
		}
		byte[] dst = new byte[len];
		System.arraycopy(src, offset, dst, 0, len);
		return dst;
	}

	/**
	 * Concatenates given arrays.
	 *
	 * @param arrays    Arrays to be concatenated
	 * @return concatenated byte array
	 */
	public static byte[] concat(byte[]... arrays) {
		int totalLength = 0;
		for (int i = 0; i < arrays.length; i++) {
			totalLength += arrays[i].length;
		}

		byte[] result = new byte[totalLength];
		int pos = 0;

		for (int i = 0; i < arrays.length; i++) {
			System.arraycopy(arrays[i], 0, result, pos, arrays[i].length);
			pos += arrays[i].length;
		}
		return result;
	}

	/**
	 * Converts array of integers to byte array.
	 *
	 * @param arrays Integer array
	 * @return Converted byte array
	 */
	public static byte[] intArrayToByteArray(int[] arrays) {
		byte[] bytes = new byte[arrays.length * 4];
		int pos = 0;
		for (int i = 0; i < arrays.length; i++) {
			System.arraycopy(ByteBuffer.allocate(4).putInt(arrays[i]).array(), 0, bytes, pos, 4);
			pos += 4;
		}
		return bytes;
	}
}
