/*
 * Copyright 2020-2021 NXP.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.nxp.iot.devicelink;

/**
 * Class containing tlv data frame which will be sent over TCP.
 */
public class TlvFrame {
	public short cmd;
	public short length;
	public byte[] payload;
}
