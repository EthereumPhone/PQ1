/*
 * Copyright 2020-2021 NXP.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.nxp.iot.devicelink;

import java.util.List;

public class JsonProvisioning {
	public String deviceId;
	public List<RtpDeviceProvisioning> rtpProvisionings;

	public List<RtpDeviceProvisioning> getRtpProvisionings() {
		return rtpProvisionings;
	}

	public static class Apdu {
		public byte[] apdu;
	}

	public static class SecureObject {
		public String type;
		public Long id;
		public String name;
		public String objectId;
		public String algorithm;
		public String algorithmType;
		public Long keyPairId;
		public Long length;
		public String publicKey;
	}

	public static class Apdus {
		public Apdu createApdu;
		public List<Apdu> writeApdus;

		public List<Apdu> getWriteApdus() {
			return writeApdus;
		}
	}

	public static class RtpDeviceProvisioning {
		public Long provisioningId;
		public SecureObject secureObject;
		public String state;
		public Apdus apdus;
	}
}
